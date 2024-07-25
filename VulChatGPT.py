import functools
import json
import idaapi
import ida_hexrays
import ida_kernwin
import idc
import os
import re
import textwrap
import threading
import ollama

# =============================================================================
# Setup the context menu and hotkey in IDA
# =============================================================================

class VulChatPlugin(idaapi.plugin_t):
    flags = 0 
    vuln_action_name = "vulchat:vuln_function"
    vuln_menu_path = "Edit/VulChat/Find Possible Vulnerability"
    expl_action_name = "vulchat:expl_function"
    expl_menu_path = "Edit/Vulchat/Write Python Explain Sample Script"
    analyze_action_name = "vulchat:analyze_function"
    analyze_menu_path = "Edit/Vulchat/Analyze the following Code"
    wanted_name = 'VulChat'
    wanted_hotkey = ''
    comment = "Uses Ollama API to find vulnerabilities in the decompiler's output"
    help = "See usage instructions on GitHub"
    menu = None

    def init(self):
        # Check whether the decompiler is available
        if not ida_hexrays.init_hexrays_plugin():
            return idaapi.PLUGIN_SKIP
        
        # Function analyzeing action
        analyze_action = idaapi.action_desc_t(self.analyze_action_name,
                                              'Analyze function',
                                              AnalyzeHandler(),
                                              "Ctrl+Alt+A",
                                              'Use Ollama API to analyze the currently selected function',
                                              199)
        idaapi.register_action(analyze_action)
        idaapi.attach_action_to_menu(self.analyze_menu_path, self.analyze_action_name, idaapi.SETMENU_APP)

        # Function vulnerability Checker
        vuln_action = idaapi.action_desc_t(self.vuln_action_name,
                                           'Vulnerability function',
                                           VulnHandler(),
                                           "Ctrl+Alt+V",
                                           "Use Ollama API to find possible vulnerability in decompiled function",
                                           199)
        idaapi.register_action(vuln_action)
        idaapi.attach_action_to_menu(self.vuln_menu_path, self.vuln_action_name, idaapi.SETMENU_APP)

        # Function Explain Creator
        explain_action = idaapi.action_desc_t(self.expl_action_name,
                                              'Explain API',
                                              ExplainHandler(),
                                              "Ctrl+Alt+A",
                                              "Use Ollama API to explain the API",
                                              199)
        idaapi.register_action(explain_action)
        idaapi.attach_action_to_menu(self.expl_menu_path, self.expl_action_name, idaapi.SETMENU_APP)

        # Register context menu actions
        self.menu = ContextMenuHooks()
        self.menu.hook()

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.analyze_menu_path, self.analyze_action_name)
        idaapi.detach_action_from_menu(self.vuln_menu_path, self.vuln_action_name)
        idaapi.detach_action_from_menu(self.expl_menu_path, self.expl_action_name)
        if self.menu:
            self.menu.unhook()
        return

# -----------------------------------------------------------------------------

class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            idaapi.attach_action_to_popup(form, popup, VulChatPlugin.analyze_action_name, "VulChat/Analyze_Function")
            idaapi.attach_action_to_popup(form, popup, VulChatPlugin.expl_action_name, "VulChat/Explain_API")
            idaapi.attach_action_to_popup(form, popup, VulChatPlugin.vuln_action_name, "VulChat/")



# -----------------------------------------------------------------------------

def comment_callback(address, view, response):
    """
    Callback that sets a comment at the given address.
    :param address: The address of the function to comment
    :param view: A handle to the decompiler window
    :param response: The comment to add
    """
    # Add newlines at the end of each sentence.
    response = "\n".join(textwrap.wrap(response, 80, replace_whitespace=False))

    # Add the response as a comment in IDA.
    idc.set_func_cmt(address, response, 0)
    # Refresh the window so the comment is displayed properly
    if view:
        view.refresh_view(False)
    print("Ollama API query finished!")
    
# -----------------------------------------------------------------------------

class AnalyzeHandler(idaapi.action_handler_t):
    """
    This handler is tasked with querying Ollama API for an explanation of the
    given function. Once the reply is received, it is added as a function
    comment.
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async("您能否详细说明以下代码的用途并为其提出一个更具描述性的名称？最后总结给出这个函数做了什么事\n"
                          + str(decompiler_output),
                          functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# -----------------------------------------------------------------------------

class VulnHandler(idaapi.action_handler_t):
    """
    This handler is tasked with querying Ollama API for a possible check of vulnerabilities on a given function.
    Once the reply is received its added to the function as a comment.
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async("""您是CTF比赛中的一名二进制漏洞分析师。
                            您的任务是帮助参赛者分析他们提供的二进制文件派生的反编译 C 语言文件。
                            您必须首先给出漏洞的可能性
                            请记住，您只能访问 C 语言文件，而不能要求提供有关文件的任何其他信息。
                            当您给出答案时，您必须给出漏洞的位置以及它成为漏洞的原因，否则，您无法回答。
                            利用您的专业知识彻底分析 C 语言文件并为参赛者提供有价值的见解。
                            提示：CTF 比赛中的一名参赛者刚刚向您提交了一个反编译的 C 语言文件以供分析。
                            他们正在寻找任何可能有助于他们参加比赛的潜在漏洞、弱点或线索。
                            仅使用 C 语言文件中提供的信息，提供详细分析，突出显示任何感兴趣或关注的领域。
                            不要生成不确定的信息

                            常见漏洞：
                            Stack overflow,Array out of bounds,Format string vulnerability,Wild pointer,Heap overflow,Off by one,UAF,Double free ...

                            以下是一些示例：

                            我可能在代码中检测到了 xxx。具体来说是在 xxxx() 函数中。代码使用 xxx 到 xxx，这可能导致 xxxx。（请给出您的解释）

                            xxxxx() 函数中存在 xxx（漏洞）。（请给出您的解释）

                            请分析此格式的代码并给出非常肯定的答案。

                            \n"""
        + str(decompiler_output),
        functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# -----------------------------------------------------------------------------
class ExplainHandler(idaapi.action_handler_t):
    """
    This handler requests a python explain for the vulnerable function
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        decompiler_output = ida_hexrays.decompile(idaapi.get_screen_ea())
        v = ida_hexrays.get_widget_vdui(ctx.widget)
        query_model_async("分析这个函数:\n" + str(decompiler_output) + 
        """\n
        请直接分析其中代码所使用的所有windows API，标注序号并给出解释，实例如下：

        1.API名称1:给出你的解释
        2.API名称2:给出你的解释

        注意:不要生成其余额外的东西，严格按照格式进行生成

        """,
        functools.partial(comment_callback, address=idaapi.get_screen_ea(), view=v))
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS   

# =============================================================================
# Ollama API interaction
# =============================================================================

def query_model(query, cb):
    """
    Function which sends a query to Ollama API and calls a callback when the response is available.
    Blocks until the response is received
    :param query: The request to send to Ollama API
    :param cb: The function to which the response will be passed to.
    """
    try:
        response = ollama.chat(model='codeqwen', messages=[
            {'role': 'user', 'content': query}
        ])
        # Use the content of the message from the response
        ida_kernwin.execute_sync(functools.partial(cb, response=response['message']['content']), ida_kernwin.MFF_WRITE)
    except Exception as e:
        print(f"Ollama API could not complete the request: {str(e)}")

# -----------------------------------------------------------------------------

def query_model_async(query, cb):
    """
    Function which sends a query to Ollama API and calls a callback when the response is available.
    :param query: The request to send to Ollama API
    :param cb: The function to which the response will be passed to.
    """
    print("Request to Ollama API sent...")
    t = threading.Thread(target=query_model, args=[query, cb])
    t.start()

# =============================================================================
# Main
# =============================================================================

def PLUGIN_ENTRY():
    return VulChatPlugin()
