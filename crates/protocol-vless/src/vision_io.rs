//! 在 Vision 判定 END/Direct 前限制明文读取边界，避免 TLS 驱动预读下一段裸流。
use crate::UserId;
use std::{io,pin::Pin,task::{Context,Poll}};
use tokio::io::{AsyncRead,AsyncWrite,ReadBuf};
use xray_proxy::vless::VisionStreamIo;
use xray_transport::BoxedTransportStream;

#[derive(Clone,Copy)]
enum Stage {ResponseVersion,ResponseLength,ResponseBody(usize),Prefix,Header,Body(usize),Released}
struct Boundary {stage:Stage,user:[u8;16],prefix:[u8;16],prefix_len:usize,header:[u8;5],header_len:usize}
impl Boundary {
    fn new(user:UserId,client:bool)->Self {Self {stage:if client{Stage::ResponseVersion}else{Stage::Prefix},user:*user.as_bytes(),prefix:[0;16],prefix_len:0,header:[0;5],header_len:0}}
    fn limit(&self,size:usize)->usize {size.min(match self.stage {Stage::ResponseVersion|Stage::ResponseLength|Stage::Prefix=>1,Stage::ResponseBody(n)|Stage::Body(n)=>n,Stage::Header=>5-self.header_len,Stage::Released=>size})}
    fn observe(&mut self,bytes:&[u8]) {
        match self.stage {
            Stage::ResponseVersion=>self.stage=Stage::ResponseLength,
            Stage::ResponseLength=>self.stage=if bytes[0]==0{Stage::Prefix}else{Stage::ResponseBody(bytes[0] as usize)},
            Stage::ResponseBody(n)=>{let remaining=n-bytes.len();self.stage=if remaining==0{Stage::Prefix}else{Stage::ResponseBody(remaining)};},
            Stage::Prefix=>{
                self.prefix[self.prefix_len]=bytes[0];self.prefix_len+=1;
                if self.prefix[..self.prefix_len]==self.user[..self.prefix_len] {if self.prefix_len==16 {self.stage=Stage::Header;}return;}
                // 兼容省略首个 UUID 前缀的帧；已交付的探测字节仍计入真实帧边界。
                self.stage=Stage::Header;let prefix=self.prefix;self.framed(&prefix[..self.prefix_len]);
            },
            Stage::Header|Stage::Body(_)=>self.framed(bytes),
            Stage::Released=>{},
        }
    }
    fn framed(&mut self,mut bytes:&[u8]) {while !bytes.is_empty(){match self.stage {
        Stage::Header=>{let count=(5-self.header_len).min(bytes.len());self.header[self.header_len..self.header_len+count].copy_from_slice(&bytes[..count]);self.header_len+=count;bytes=&bytes[count..];if self.header_len==5 {let size=u16::from_be_bytes([self.header[1],self.header[2]]) as usize+u16::from_be_bytes([self.header[3],self.header[4]]) as usize;self.header_len=0;self.stage=if size==0{Stage::Header}else{Stage::Body(size)};}},
        Stage::Body(size)=>{let count=size.min(bytes.len());bytes=&bytes[count..];self.stage=if count==size{Stage::Header}else{Stage::Body(size-count)};},
        _=>return,
    }}}
}
pub(crate) struct VisionCarrier {inner:BoxedTransportStream,boundary:Boundary}
impl VisionCarrier {pub fn new(inner:BoxedTransportStream,user:UserId,client:bool)->Self {Self {inner,boundary:Boundary::new(user,client)}}}
impl AsyncRead for VisionCarrier {
    fn poll_read(self:Pin<&mut Self>,cx:&mut Context<'_>,out:&mut ReadBuf<'_>)->Poll<io::Result<()>> {
        let this=self.get_mut();if out.remaining()==0{return Poll::Ready(Ok(()));}
        let limit=this.boundary.limit(out.remaining());let mut buffer=ReadBuf::new(out.initialize_unfilled_to(limit));
        let result=Pin::new(&mut this.inner).poll_read(cx,&mut buffer);
        if let Poll::Ready(Ok(()))=result {let count=buffer.filled().len();if count>0{this.boundary.observe(buffer.filled());}out.advance(count);}result
    }
}
impl AsyncWrite for VisionCarrier {
    fn poll_write(self:Pin<&mut Self>,cx:&mut Context<'_>,bytes:&[u8])->Poll<io::Result<usize>> {Pin::new(&mut self.get_mut().inner).poll_write(cx,bytes)}
    fn poll_flush(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {Pin::new(&mut self.get_mut().inner).poll_flush(cx)}
    fn poll_shutdown(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)}
}
impl VisionStreamIo for VisionCarrier {
    fn release_record_alignment(&mut self){self.boundary.stage=Stage::Released;self.inner.release_record_alignment();}
    fn poll_read_direct(self:Pin<&mut Self>,cx:&mut Context<'_>,out:&mut ReadBuf<'_>)->Poll<io::Result<()>> {let this=self.get_mut();this.boundary.stage=Stage::Released;Pin::new(&mut *this.inner).poll_read_direct(cx,out)}
    fn poll_write_direct(self:Pin<&mut Self>,cx:&mut Context<'_>,bytes:&[u8])->Poll<io::Result<usize>> {Pin::new(&mut *self.get_mut().inner).poll_write_direct(cx,bytes)}
    fn poll_flush_direct(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {Pin::new(&mut *self.get_mut().inner).poll_flush_direct(cx)}
    fn poll_shutdown_direct(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<io::Result<()>> {Pin::new(&mut *self.get_mut().inner).poll_shutdown_direct(cx)}
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use xray_proxy::vless::{VisionCommand,VisionPadding,VisionStream,VlessResponseStream,DEFAULT_VISION_SEED};
    use xray_transport::TransportStream;
    struct Guarded {plain:std::io::Cursor<Vec<u8>>,raw:std::io::Cursor<Vec<u8>>,chunk:usize}
    impl AsyncRead for Guarded {
        fn poll_read(self:Pin<&mut Self>,_:&mut Context<'_>,out:&mut ReadBuf<'_>)->Poll<io::Result<()>> {let this=self.get_mut();let at=this.plain.position() as usize;let left=this.plain.get_ref().len()-at;if out.remaining()>left{return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData,"TLS 驱动预读了 Direct 后的裸记录")));}let count=out.remaining().min(this.chunk);out.put_slice(&this.plain.get_ref()[at..at+count]);this.plain.set_position((at+count) as u64);Poll::Ready(Ok(()))}
    }
    impl AsyncWrite for Guarded {fn poll_write(self:Pin<&mut Self>,_:&mut Context<'_>,bytes:&[u8])->Poll<io::Result<usize>>{Poll::Ready(Ok(bytes.len()))}fn poll_flush(self:Pin<&mut Self>,_:&mut Context<'_>)->Poll<io::Result<()>>{Poll::Ready(Ok(()))}fn poll_shutdown(self:Pin<&mut Self>,_:&mut Context<'_>)->Poll<io::Result<()>>{Poll::Ready(Ok(()))}}
    impl TransportStream for Guarded {fn poll_read_direct(self:Pin<&mut Self>,cx:&mut Context<'_>,out:&mut ReadBuf<'_>)->Poll<io::Result<()>>{Pin::new(&mut self.get_mut().raw).poll_read(cx,out)}fn poll_write_direct(self:Pin<&mut Self>,cx:&mut Context<'_>,bytes:&[u8])->Poll<io::Result<usize>>{self.poll_write(cx,bytes)}}
    #[tokio::test]
    async fn direct_boundary_preserves_raw_records_and_fragmented_response_addons(){
        let user=UserId::from_bytes([0;16]);let mut padding=VisionPadding::new(*user.as_bytes(),DEFAULT_VISION_SEED);
        let mut wire=vec![0,3,7,8,9];let mut block=bytes::BytesMut::new();padding.pad_into(b"hello",VisionCommand::Continue,13,&mut block).unwrap();padding.pad_into(b"tls",VisionCommand::Direct,7,&mut block).unwrap();wire.extend_from_slice(&block);
        for chunk in [1,3,8192] {let io=Guarded {plain:std::io::Cursor::new(wire.clone()),raw:std::io::Cursor::new(b"raw-record".to_vec()),chunk};let carrier=VisionCarrier::new(Box::new(io),user,true);let mut stream=VisionStream::new(VlessResponseStream::new(carrier),*user.as_bytes(),DEFAULT_VISION_SEED);let mut output=Vec::new();stream.read_to_end(&mut output).await.unwrap();assert_eq!(output,b"hellotlsraw-record");}
    }
    #[tokio::test]
    async fn prefixless_and_empty_frames_keep_the_next_header_aligned(){
        let user=UserId::from_bytes([0;16]);let wire=vec![0,0,0,0,0,2,0,3,0,0,b't',b'l',b's'];
        let io=Guarded {plain:std::io::Cursor::new(wire),raw:std::io::Cursor::new(b"raw".to_vec()),chunk:1};let mut stream=VisionStream::new(VisionCarrier::new(Box::new(io),user,false),*user.as_bytes(),DEFAULT_VISION_SEED);let mut output=Vec::new();stream.read_to_end(&mut output).await.unwrap();assert_eq!(output,b"tlsraw");
    }
}
