# No-function-missed audit: for each tree-sitter language, parse a diverse snippet,
# count NAMED functions/methods the grammar sees, and confirm the extractor emits an
# IR function for each. Any named func in the tree but absent from IR = a MISS.
import sys,os,importlib
sys.path.insert(0,'agent_a'); sys.path.insert(0,'agent_a/ts_extract')
from tree_sitter_language_pack import get_parser
import extract as EX

# (lang, ext, source with several named functions/methods + a lambda)
CASES = {
 'python':('py','''
def top(a): return a
class C:
    def meth(self): pass
    @staticmethod
    def st(): pass
    async def am(self): pass
def outer():
    def inner(): pass
    return inner
f = lambda x: x+1
'''),
 'javascript':('js','''
function top(a){return a}
const arrow = (x)=>x+1;
class C { meth(){} static st(){} async am(){} }
async function af(){}
function* gen(){}
const obj = { m(){}, p: function named(){} };
'''),
 'typescript':('ts','''
function top(a:number):number{return a}
const arrow = (x:number)=>x+1;
class C { meth():void{} static st(){} private pr(){} }
export function ex(){}
interface I { m():void }
'''),
 'java':('java','''
class A {
  void top(){}
  static int st(){return 0;}
  public String meth(String s){return s;}
  interface I { void m(); }
  Runnable r = () -> {};
}
'''),
 'csharp':('cs','''
class A {
  void Top(){}
  static int St()=>0;
  public string Meth(string s){return s;}
  public int Prop { get; set; }
  System.Action a = () => {};
}
'''),
 'cpp':('cpp','''
int top(int a){return a;}
class C { public: void meth(); static int st(); };
void C::meth(){}
auto lam = [](int x){return x+1;};
namespace n { void inns(){} }
'''),
 'ruby':('rb','''
def top(a); a; end
class C
  def meth; end
  def self.st; end
end
module M; def mm; end; end
p = ->(x){ x+1 }
'''),
 'php':('php','''<?php
function top($a){return $a;}
class C {
  public function meth(){}
  public static function st(){}
}
$f = function($x){return $x;};
$a = fn($x) => $x+1;
'''),
 'perl':('pl','''
sub top { my $a=shift; return $a; }
package P;
sub meth { }
my $code = sub { return 1; };
'''),
 'kotlin':('kt','''
fun top(a:Int):Int = a
class C { fun meth(){} companion object { fun st(){} } }
val lam = { x:Int -> x+1 }
fun C.ext(){}
'''),
 'swift':('swift','''
func top(_ a:Int)->Int{return a}
class C { func meth(){} static func st(){} }
let lam = { (x:Int) in x+1 }
extension C { func ext(){} }
'''),
 'rust':('rs','''
fn top(a:i32)->i32{a}
struct S;
impl S { fn meth(&self){} fn st(){} }
trait T { fn tm(&self); }
let clo = |x:i32| x+1;
'''),
 'objc':('m','''
void top(int a){}
@interface C : NSObject
- (void)meth;
+ (int)st;
@end
@implementation C
- (void)meth {}
+ (int)st { return 0; }
@end
'''),
 'vbnet':('vb','''
Module M
  Sub Top()
  End Sub
  Function Meth(s As String) As String
    Return s
  End Function
End Module
Class C
  Public Sub M2()
  End Sub
End Class
'''),
}

def run():
    import run_lang
    print('%-12s %-7s %-7s %s'%('LANG','TREE','IR','MISSED NAMED FUNCS'))
    total_miss=0
    for lang,(ext,src) in CASES.items():
        fam = run_lang.LANG_FAMILY.get(lang,lang)
        try:
            plug = importlib.import_module('plugins.'+lang)
        except Exception as e:
            print('%-12s  plugin import ERR %s'%(lang,e)); continue
        parser = get_parser(plug.TS_LANG)
        tree = parser.parse(src.encode())
        FT=set(getattr(plug,'FUNC_TYPES',set())); 
        # collect named functions from the tree
        named=[]
        def walk(n):
            if n.type in FT:
                try: nm=plug.func_name(n, src.encode())
                except Exception: nm=''
                if nm: named.append(nm)
            for c in n.children: walk(c)
        walk(tree.root_node)
        named=sorted(set(named))
        # extract IR
        d='%s/tmp/cmp_%s'%(os.environ.get('CLAUDE_JOB_DIR','/tmp'),lang); os.makedirs(d,exist_ok=True)
        open(os.path.join(d,'a.'+ext),'w').write(src)
        try:
            ir = run_lang.extract_ir(lang, d)
            irnames=set()
            for fn in ir.get('functions',[]) if isinstance(ir,dict) else ir:
                nm = fn.get('name') if isinstance(fn,dict) else None
                if nm: irnames.add(nm)
        except Exception as e:
            print('%-12s  extract ERR %s'%(lang,e)); continue
        missed=[n for n in named if n not in irnames]
        total_miss+=len(missed)
        print('%-12s %-7d %-7d %s'%(lang,len(named),len(irnames),','.join(missed) if missed else 'OK'))
    print('\nTOTAL NAMED-FUNC MISSES:',total_miss)

run()
