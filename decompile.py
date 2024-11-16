import functools
import idaapi
import ida_kernwin
import idc
import idautils
import threading
import ollama
import re

# =============================================================================
# Setup the context menu and hotkey in IDA
# =============================================================================

class VulChatPlugin(idaapi.plugin_t):
    flags = 0 
    analyze_action_name = "vulchat:analyze_code_segment"
    analyze_menu_path = "Edit/Vulchat/Analyze Code Segment"
    wanted_name = 'VulChat'
    wanted_hotkey = ''
    comment = "Uses Ollama API to analyze the code segment of the current file"
    help = "See usage instructions on GitHub"
    menu = None

    def init(self):
        # Register action for analyzing the code segment
        analyze_action = idaapi.action_desc_t(self.analyze_action_name,
                                              'Analyze Code Segment',
                                              AnalyzeCodeSegmentHandler(),
                                              "Ctrl+Alt+P",
                                              'Use Ollama API to analyze the code segment of the current file',
                                              199)
        idaapi.register_action(analyze_action)
        idaapi.attach_action_to_menu(self.analyze_menu_path, self.analyze_action_name, idaapi.SETMENU_APP)

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.analyze_menu_path, self.analyze_action_name)
        return

# ----------------------------------------------------------------------------- 

class AnalyzeCodeSegmentHandler(idaapi.action_handler_t):
    """
    This handler sends only the code segment of the disassembled file to Ollama API for analysis.
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Get disassembled content of the code segment
        disasm_content = get_code_segment_disassembly()
        print(disasm_content)
        # Send the disassembly to Ollama API
        query_model_async("This is the assembly code:\n" + disasm_content + "\nWhat is the source code?\n",
                          handle_response)
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

# ----------------------------------------------------------------------------- 

def get_code_segment_disassembly():
    """
    Retrieves the disassembled content of the code segment (.text) of the current IDA file.
    Removes any string literals or comments after ';' in the disassembly lines.
    """
    disasm_content = []
    
    # Iterate over all segments to find the code segment (usually ".text")
    for seg in idautils.Segments():
        seg_name = idc.get_segm_name(seg)
        if seg_name == ".text":  # Assuming ".text" is the code segment
            for ea in idautils.Heads(idc.get_segm_start(seg), idc.get_segm_end(seg)):
                disasm_line = idc.generate_disasm_line(ea, 0)
                if disasm_line:
                    # Remove the part of the line after ';' (comments or string literals)
                    disasm_line = re.sub(r'\s*;.*$', '', disasm_line)
                    disasm_content.append(disasm_line)
            break  # Only analyze the first code segment found

    return "\n".join(disasm_content)

# ----------------------------------------------------------------------------- 

def handle_response(response):
    """
    Handle the response from Ollama API and display it in a new IDA text window.
    """
    # Get the response content
    response_text = response.get('message', {}).get('content', 'No response content')
    
    # Print to console for debugging
    print("Analysis Finished")

    
    # Create a new text window and display the response
    title = "Analysis Output"
    form = idaapi.simplecustviewer_t()
    if form.Create(title):
        form.ClearLines()
        form.AddLine("Analysis Result:")
        form.AddLine("")
        for line in response_text.splitlines():
            form.AddLine(line)
        form.Show()
    else:
        print("Failed to create a new text window in IDA.")

# =============================================================================
# Ollama API interaction
# =============================================================================

def query_model(query, cb):
    """
    Function which sends a query to Ollama API and calls a callback when the response is available.
    Blocks until the response is received.
    :param query: The request to send to Ollama API
    :param cb: The function to which the response will be passed.
    """
    try:
        response = ollama.chat(model='deepseek-coder-6.7B-base-v2-F16', messages=[{'role': 'user', 'content': query}])
        # Call the callback with the response llm4decompile-1.3B-v2-F16
        ida_kernwin.execute_sync(functools.partial(cb, response=response), ida_kernwin.MFF_WRITE)
    except Exception as e:
        print(f"Ollama API could not complete the request: {str(e)}")

# ----------------------------------------------------------------------------- 

def query_model_async(query, cb):
    """
    Function which sends a query to Ollama API and calls a callback when the response is available.
    :param query: The request to send to Ollama API
    :param cb: The function to which the response will be passed.
    """
    print("Request to sent...")
    t = threading.Thread(target=query_model, args=[query, cb])
    t.start()

# =============================================================================
# Main
# =============================================================================

def PLUGIN_ENTRY():
    return VulChatPlugin()
