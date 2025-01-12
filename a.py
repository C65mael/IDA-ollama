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

class DecChatPlugin(idaapi.plugin_t):
    flags = 0 
    decompile_action_name = "decchat:decompile_code_segment"
    decompile_menu_path = "Edit/Decchat/Decompile Code Segment"
    wanted_name = 'DecChat'
    wanted_hotkey = ''
    comment = "Use Ollama API to decompile the code segment"
    help = "See usage instructions on GitHub"
    menu = None

    def init(self):
        # Register action for decompiling the code segment
        decompile_action = idaapi.action_desc_t(self.decompile_action_name,
                                              'Decompile',
                                              DecompileCodeSegmentHandler(),
                                              "Ctrl+Alt+P",
                                              'Use Ollama API to decompile the code segment',
                                              199)
        idaapi.register_action(decompile_action)
        idaapi.attach_action_to_menu(self.decompile_menu_path, self.decompile_action_name, idaapi.SETMENU_APP)

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        idaapi.detach_action_from_menu(self.decompile_menu_path, self.decompile_action_name)
        return

# ----------------------------------------------------------------------------- 

class DecompileCodeSegmentHandler(idaapi.action_handler_t):
    """
    This handler sends only the code segment of the disassembled file to Ollama API for decompile.
    """
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        # Get disassembled content of the code segment
        disasm_content = get_code_segment_disassembly()
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
    """
    disasm_content = []
    
    # Iterate over all segments to find the code segment (usually ".text")
    for seg in idautils.Segments():
        seg_name = idc.get_segm_name(seg)
        if seg_name == ".text" or seg_name == "CODE":  # Assuming ".text" is the code segment
            for ea in idautils.Heads(idc.get_segm_start(seg), idc.get_segm_end(seg)):
                disasm_line = idc.generate_disasm_line(ea, 0)
                if disasm_line:
                    disasm_content.append(disasm_line)
            break  # Only decompile the first code segment found

    return "\n".join(disasm_content)

# ----------------------------------------------------------------------------- 

def handle_response(response):
    """
    Handle the response from Ollama API and display it in a new IDA text window.
    """
    # Get the response content from stream
    response_text = response.get('message', {}).get('content', 'No response content')
    
    # Print to console for debugging
    print("Decompile Finished")

    # Create a new text window and display the response
    title = "Decompile Output"
    form = idaapi.simplecustviewer_t()
    if form.Create(title):
        form.ClearLines()
        form.AddLine("Decompiled Result:")
        form.AddLine("")

        # Display response content in chunks (streamed response)
        for line in response_text.splitlines():
            form.AddLine(line)
        form.Show()
    else:
        print("Failed to create a new text window in IDA.")

# =============================================================================
# Ollama API interaction with stream support
# =============================================================================

def query_model(query, cb):
    """
    Function which sends a query to Ollama API and calls a callback when the response is available.
    Blocks until the response is received.
    :param query: The request to send to Ollama API
    :param cb: The function to which the response will be passed to.
    """
    try:
        # Enable streaming output for real-time updates
        response = ollama.chat(model='Yi-Coder-9B-9-F16-q4', messages=[{'role': 'user', 'content': query}],
        options={
            "temperature": 0.1,       # Setting a lower temperature improves accuracy
            "num_beams": 5,           # Using beam search to improve quality
            "max_new_tokens": 2048,    # Limit the number of new tokens generated
            "stream": True            # Enable streaming to get real-time response
        })
        
        # Execute callback with streamed response content
        ida_kernwin.execute_sync(functools.partial(cb, response=response), ida_kernwin.MFF_WRITE)
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
    return DecChatPlugin()
