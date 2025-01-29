import functools
import idaapi
import ida_kernwin
import idc
import idautils
import threading
import ollama
import ida_hexrays

# =============================================================================
# 伪代码分析插件
# =============================================================================

class DecChatPlugin(idaapi.plugin_t):
    flags = 0
    action_name = "decchat:analyze_pseudocode"
    menu_path = "Edit/Decchat/Analyze Pseudocode"
    wanted_name = 'Pseudocode Analyzer'
    wanted_hotkey = ''
    comment = "Use AI to analyze decompiled pseudocode"
    help = "Requires Hex-Rays decompiler"

    def init(self):
        action_desc = idaapi.action_desc_t(
            self.action_name,
            'Analyze Pseudocode',
            PseudocodeHandler(),
            "Ctrl+Alt+P",
            'Send pseudocode to AI for analysis',
            199
        )
        idaapi.register_action(action_desc)
        idaapi.attach_action_to_menu(self.menu_path, self.action_name, idaapi.SETMENU_APP)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.menu_path, self.action_name)

# -----------------------------------------------------------------------------

class PseudocodeHandler(idaapi.action_handler_t):
    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        code = get_pseudocode()
        if code:
            prompt = f"This is the decompiled code:\n{code}\nWhat is the source code?"
            query_model_async(prompt, response_handler)
        else:
            print("Error: No pseudocode available")
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# -----------------------------------------------------------------------------

def get_pseudocode():
    """获取当前反编译窗口内容"""
    try:
        # 方法1：使用Hex-Rays API获取结构化伪代码
        widget = idaapi.get_current_widget()
        vu = ida_hexrays.get_widget_vdui(widget)
        if vu and vu.cfunc:
            return "\n".join([item.line for item in vu.cfunc.get_pseudocode()])

        # 方法2：直接从文本视图读取
        viewer = idaapi.get_current_viewer()
        return "\n".join(
            idaapi.get_custom_viewer_curline(viewer, i)
            for i in range(idaapi.get_line_qty(viewer))
        )

    except Exception as e:
        print(f"Pseudocode fetch failed: {str(e)}")
        return None

# -----------------------------------------------------------------------------

def response_handler(response):
    """处理AI响应"""
    content = response.get('message', {}).get('content', 'No analysis available')
    
    # 创建显示窗口
    title = "AI Analysis Result"
    viewer = idaapi.simplecustviewer_t()
    if viewer.Create(title):
        viewer.ClearLines()
        viewer.AddLine("🤖 AI Analysis:")
        viewer.AddLine("=" * 80)
        for line in content.splitlines():
            viewer.AddLine(line.rstrip())
        viewer.Show()
    else:
        print("Failed to create result window")

# =============================================================================
# Ollama交互模块
# =============================================================================

def query_model(query, cb):
    try:
        print("Request...")
        response = ollama.chat(
            model='llm4decompile-6.7b-v2',
            messages=[{'role': 'user', 'content': query}],
            options={
                # "temperature": 0.1,
                # "num_beams": 9,
                # "max_new_tokens": 2048
                "temperature": 0.3,
                "num_beams": 5,
                "max_new_tokens": 3072,
                "top_p": 0.9,
                "repetition_penalty": 1.2
            }
        )
        ida_kernwin.execute_sync(functools.partial(cb, response=response), ida_kernwin.MFF_WRITE)
    except Exception as e:
        print(f"API Error: {str(e)}")

def query_model_async(query, cb):
    threading.Thread(target=query_model, args=(query, cb)).start()

# =============================================================================
# 入口函数
# =============================================================================

def PLUGIN_ENTRY():
    return DecChatPlugin()