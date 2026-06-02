import json

PATH = "packets.json"

KEYS = {
    0x01: "<ESC>", 0x0e: "<BACKSPACE>", 0x0f: "\t", 0x1c: "\n",
    0x1d: "<CTRL>", 0x38: "<ALT>", 0x39: " ",

    0x02: "1", 0x03: "2", 0x04: "3", 0x05: "4", 0x06: "5",
    0x07: "6", 0x08: "7", 0x09: "8", 0x0a: "9", 0x0b: "0",
    0x0c: "-", 0x0d: "=",

    0x10: "q", 0x11: "w", 0x12: "e", 0x13: "r", 0x14: "t",
    0x15: "y", 0x16: "u", 0x17: "i", 0x18: "o", 0x19: "p",
    0x1a: "[", 0x1b: "]",

    0x1e: "a", 0x1f: "s", 0x20: "d", 0x21: "f", 0x22: "g",
    0x23: "h", 0x24: "j", 0x25: "k", 0x26: "l",
    0x27: ";", 0x28: "'", 0x29: "`",

    0x2b: "\\", 0x2c: "z", 0x2d: "x", 0x2e: "c", 0x2f: "v",
    0x30: "b", 0x31: "n", 0x32: "m",
    0x33: ",", 0x34: ".", 0x35: "/",

    0x47: "<HOME>", 0x48: "<UP>", 0x49: "<PGUP>",
    0x4b: "<LEFT>", 0x4d: "<RIGHT>",
    0x4f: "<END>", 0x50: "<DOWN>", 0x51: "<PGDN>",
    0x52: "<INS>", 0x53: "<DEL>",
}

SHIFTED = {
    "1": "!", "2": "@", "3": "#", "4": "$", "5": "%",
    "6": "^", "7": "&", "8": "*", "9": "(", "0": ")",
    "-": "_", "=": "+", "[": "{", "]": "}", "\\": "|",
    ";": ":", "'": '"', "`": "~", ",": "<", ".": ">", "/": "?",
}

talkings = []
shift = False

def walk(x):
    global shift

    if type(x) == dict:
        if "rdp.fastpath.scancode.keycode" in x:
            code = int(x["rdp.fastpath.scancode.keycode"], 16)
            release = x["rdp.fastpath.eventheader_tree"]["rdp.fastpath.scancode.release"] == "1"

            if code in (0x2a, 0x36):
                shift = not release
            elif not release:
                ch = KEYS.get(code, f"<{code:02x}>")

                if shift:
                    ch = SHIFTED.get(ch, ch.upper() if len(ch) == 1 else ch)

                if ch == "<BACKSPACE>":
                    if talkings:
                        talkings.pop()
                else:
                    talkings.append(ch)

        for v in x.values():
            walk(v)

    elif type(x) == list:
        for v in x:
            walk(v)

walk(json.load(open(PATH)))
print("".join(talkings))
