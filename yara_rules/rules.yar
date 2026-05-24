rule Suspicious_Node_APIs {
    meta:
        description = "Detects usage of dangerous Node.js APIs often used in malicious extensions"
        author = "ExtensionGuard"
    strings:
        $exec = "child_process.exec" ascii
        $spawn = "child_process.spawn" ascii
        $eval = "eval(" ascii
        $fs_write = "fs.writeFileSync" ascii
        $net_socket = "net.Socket()" ascii
    condition:
        any of them
}