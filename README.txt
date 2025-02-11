NOTE: 
- This program will create a startup script in %APPDATA%\Microsoft\Windows\Start Menu\Programs\startup
- It is also possible to hide the console window by uncommenting the first line of main in main.c
- Start the client, start the server, issue commands to the client from the server

1. Install GCC for Windows from https://osdn.net/projects/mingw/releases/72219

2. To compile: "gcc main.c util.c net.c hake.c -lws2_32 -o client.exe && gcc server.c -lws2_32 -o server.exe"

4. To use gdb with Visual Studio Code:

  Add this to $workspaceRoot/.vscode/launch.json:

    "configurations": [
        {
            "name": "Build and Debug Client",
            "type": "cppdbg",
            "preLaunchTask": "Debug Client",
            "request": "launch",
            "program": "${fileDirname}\\client.exe",
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}",
            "externalConsole": false,
            "MIMode": "gdb",
            "miDebuggerPath": "C:\\MinGW\\bin\\gdb.exe",
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                }
            ],
        },
        {
            "name": "Build and Debug Server",
            "type": "cppdbg",
            "preLaunchTask": "Debug Server",
            "request": "launch",
            "program": "${fileDirname}\\server.exe",
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}",
            "externalConsole": false,
            "MIMode": "gdb",
            "miDebuggerPath": "C:\\MinGW\\bin\\gdb.exe",
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                }
            ],
        },
    ]

  And this to $workspaceRoot/.vscode/tasks.json:

    "tasks": [
      {
        "type": "shell",
        "label": "Debug Client",
        "command": "C:\\MinGW\\bin\\gcc.exe",
        "args": [
          "-g",
          "main.c",
          "fingerprint.c",
          "util.c",
          "net.c",
          "hake.c",
          "-o",
          "client.exe",
          "-lws2_32",
        ],
        "options": {
          "cwd": "${fileDirname}"
        }
      },
      {
        "type": "shell",
        "label": "Debug Server",
        "command": "C:\\MinGW\\bin\\gcc.exe",
        "args": [
          "-g",
          "server.c",
          "-o",
          "server.exe",
          "-lws2_32",
        ],
        "options": {
          "cwd": "${fileDirname}"
        }
      },
    ],

5. With the Code Runner extension, you can include the following in $workspaceRoot/.vscode/settings.json so compiling/executing is easy with ctrl + alt + n:

  "code-runner.executorMap": {
        "c": "cd $workspaceRoot && gcc -g main.c fingerprint.c util.c net.c hake.c -lws2_32 -o client.exe && gcc -g server.c -lws2_32 -o server.exe && start client.exe && start server.exe"
    }