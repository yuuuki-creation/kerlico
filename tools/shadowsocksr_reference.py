"""仅在 worker 启动固定 Python SSR 测试对端，兼容宿主 Python/OpenSSL API。"""
import argparse,collections,collections.abc,ctypes,ctypes.util,runpy,sys,warnings
sys.dont_write_bytecode=True
warnings.filterwarnings('ignore',category=SyntaxWarning)
p=argparse.ArgumentParser();p.add_argument('--reference',required=True);p.add_argument('--role',choices=['client','server'],required=True);p.add_argument('--config',required=True);a=p.parse_args()
collections.MutableMapping=collections.abc.MutableMapping
lib=ctypes.CDLL(ctypes.util.find_library('crypto'))
if hasattr(lib,'OSSL_PROVIDER_load'):
 lib.OSSL_PROVIDER_load.argtypes=[ctypes.c_void_p,ctypes.c_char_p];lib.OSSL_PROVIDER_load.restype=ctypes.c_void_p
 assert lib.OSSL_PROVIDER_load(None,b'default') and lib.OSSL_PROVIDER_load(None,b'legacy')
sys.path.insert(0,a.reference)
from shadowsocks import common,obfs
from shadowsocks.obfsplugin import auth,auth_chain
class LegacyBytes(bytes):
 def split(self,sep=None,maxsplit=-1):return super().split(sep.encode() if isinstance(sep,str) else sep,maxsplit)
def compatible_bytes(value):
 value=common.to_bytes(value)
 return LegacyBytes(value) if isinstance(value,bytes) else value
auth.to_bytes=compatible_bytes;auth_chain.to_bytes=compatible_bytes
class ProtocolNames(list):
 def __contains__(self,value):return super().__contains__(common.to_str(value))
original_mu_protocol=obfs.mu_protocol
obfs.mu_protocol=lambda:ProtocolNames(original_mu_protocol())
sys.argv=['reference','-c',a.config,'-q','-q']
runpy.run_module('shadowsocks.local' if a.role=='client' else 'shadowsocks.server',run_name='__main__')
