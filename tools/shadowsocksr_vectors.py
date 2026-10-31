"""仅在 worker 从固定参考实现生成合成线格式向量；不承载内核业务。"""
import sys,collections,collections.abc,ctypes,ctypes.util,warnings,json,struct,time,os,random,hashlib
from pathlib import Path
sys.dont_write_bytecode=True;warnings.filterwarnings('ignore',category=SyntaxWarning);collections.MutableMapping=collections.abc.MutableMapping
lib=ctypes.CDLL(ctypes.util.find_library('crypto'))
if hasattr(lib,'OSSL_PROVIDER_load'):
 lib.OSSL_PROVIDER_load.argtypes=[ctypes.c_void_p,ctypes.c_char_p];lib.OSSL_PROVIDER_load.restype=ctypes.c_void_p
 assert lib.OSSL_PROVIDER_load(None,b'default') and lib.OSSL_PROVIDER_load(None,b'legacy')
sys.path.insert(0,sys.argv[1]);from shadowsocks import obfs,encrypt,common
from shadowsocks.obfsplugin import auth,auth_chain
class LegacyBytes(bytes):
 def split(self,sep=None,maxsplit=-1):return super().split(sep.encode() if isinstance(sep,str) else sep,maxsplit)
def compatible_bytes(value):
 value=common.to_bytes(value)
 return LegacyBytes(value) if isinstance(value,bytes) else value
auth.to_bytes=compatible_bytes;auth_chain.to_bytes=compatible_bytes
time.time=lambda:1700000000
base=b'synthetic-vector-base';user=b'synthetic-vector-user';uid=7;iv=b'\x42'*16;input=b'\x01\x7f\0\0\x01\x01\xbb'+b'vector-client-data';reply=bytes(range(64))*32;packet=b'\x01\x7f\0\0\x01\0\x35'+b'vector-udp'
records=[]
for protocol in ['origin','auth_sha1_v4','auth_aes128_md5','auth_aes128_sha1','auth_chain_a','auth_chain_b']:
 for overhead in [0,5]:
  print(protocol,overhead,flush=True)
  count=[0];seed=(protocol+str(overhead)).encode();random.seed(seed)
  def rand(n):
   out=b''
   while len(out)<n:out+=hashlib.sha256(seed+count[0].to_bytes(8,'big')).digest();count[0]+=1
   return out[:n]
  os.urandom=rand
  client=obfs.obfs(protocol);server=obfs.obfs(protocol);multi=protocol not in ['origin','auth_sha1_v4']
  for value,is_client in [(client,True),(server,False)]:
   state=value.init_data()
   if protocol!='origin':state.local_client_id=b'\x11'*4;state.connection_id=7
   info=obfs.server_info(state);info.key=encrypt.encrypt_key(base,'aes-128-cfb');info.iv=iv;info.recv_iv=iv;info.key_str=base;info.users={} if is_client or not multi else {struct.pack('<I',uid):user};info.update_user_func=lambda x:None
   info.protocol_param='7:synthetic-vector-user' if is_client and multi else '64' if not is_client else '';info.obfs_param='';info.host='127.0.0.1';info.port=1;info.head_len=30;info.tcp_mss=1460;info.buffer_size=32768;info.overhead=overhead+value.get_overhead(is_client);info.client='127.0.0.1';info.client_port=1;value.set_server_info(info)
  cframe=client.client_pre_encrypt(input);splain,ack=server.server_post_decrypt(cframe);assert splain==input
  sframe=server.server_pre_encrypt(reply);assert client.client_post_decrypt(sframe)==reply
  udp_multi=multi and not protocol.startswith("auth_chain")
  udp_client=obfs.obfs(protocol);udp_server=obfs.obfs(protocol)
  for value,is_client in [(udp_client,True),(udp_server,False)]:
   info=obfs.server_info(value.init_data());info.key=encrypt.encrypt_key(base,"aes-128-cfb");info.iv=iv;info.recv_iv=iv;info.key_str=base;info.users={} if is_client or not udp_multi else {struct.pack("<I",uid):user};info.update_user_func=lambda x:None;info.protocol_param="7:synthetic-vector-user" if is_client and udp_multi else "64" if not is_client else "";info.obfs_param="";info.host="127.0.0.1";info.port=1;info.head_len=30;info.tcp_mss=1460;info.buffer_size=32768;info.overhead=overhead+value.get_overhead(is_client);value.set_server_info(info)
  cu=udp_client.client_udp_pre_encrypt(packet);su,suid=udp_server.server_udp_post_decrypt(cu);assert su==packet
  sr=udp_server.server_udp_pre_encrypt(packet,suid);assert udp_client.client_udp_post_decrypt(sr)==packet
  records.append({'protocol':protocol,'obfs_overhead':overhead,'time':1700000000,'client_frame':list(cframe),'server_frame':list(sframe),'udp_client':list(cu),'udp_server':list(sr),'client_plain':list(input),'server_plain':list(reply),'udp_plain':list(packet),'udp_uses_user':udp_multi})
path=Path(sys.argv[2]);path.write_text(json.dumps({'source_commit':'fd723a92c488d202b407323f0512987346944136','base_password':base.decode(),'user_password':user.decode(),'uid':uid,'iv':list(iv),'records':records},separators=(',',':')));path.chmod(0o600)
print('固定参考线格式向量已生成，共12条protocol/overhead记录')
