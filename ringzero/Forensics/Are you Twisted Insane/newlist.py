src = "/home/hyp3rnov4/wordlists/rockyou.txt"
out = "rockyou_wrapped.txt"

with open(src, "r", errors="ignore") as f, open(out, "w") as o:
    for line in f:
        w = line.rstrip("\r\n")
        o.write(w + "\n")
        o.write(f"FLAG-{{{w}}}\n")
        o.write(f"Flag-{{{w}}}\n")
        o.write(f"flag-{{{w}}}\n")
        o.write(f"FLAG-{w}\n")
        o.write(f"Flag-{w}\n")
        o.write(f"flag-{w}\n")
        o.write(f"FLAG-{{{w}\n")
        o.write(f"Flag-{{{w}\n")

