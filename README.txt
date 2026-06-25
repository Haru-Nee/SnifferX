NOTAS IMPORTANTES AL DESCARGAR EL REPOSTORIO:
Es importante modificar el archivo ".tasks" y el archivo "properties.json"  que genera automáticamente al intentar compilar por primera vez el código si se utiliza visual studio como IDE para compilar el proyecto.

//en el archivo tasks PONER ATENCION A LA SIGUIENTE LINEA, deberá ser cambiada por la ruta donde esté el compilador del usuario. La ruta msotrada es un ejemplo real
  "command": "C:\\msys64\\ucrt64\\bin\\\\g++.exe"

LINEAS COMPLETAS:

{
    "tasks": [
        {
            "type": "cppbuild",
            "label": "C/C++: g++.exe build active file",
            "command": "C:\\msys64\\ucrt64\\bin\\\\g++.exe",
            "args": [
                "-fdiagnostics-color=always",
                "-g",
                
                // ==========================================
                // ARCHIVOS FUENTE PRINCIPALES
                // ==========================================
                "${file}",
                
                // ==========================================
                // ARCHIVOS DE IMGUI (NÚCLEO)
                // ==========================================
                "imgui/imgui.cpp",
                "imgui/imgui_draw.cpp",
                "imgui/imgui_widgets.cpp",
                "imgui/imgui_tables.cpp",
                
                // ==========================================
                // BACKENDS DE IMGUI (GLFW + OPENGL)
                // ==========================================
                "imgui/backends/imgui_impl_glfw.cpp",
                "imgui/backends/imgui_impl_opengl3.cpp",
                
                // ==========================================
                // ARCHIVO DE SALIDA
                // ==========================================
                "-o",
                "${fileDirname}\\${fileBasenameNoExtension}.exe",
                
                // ==========================================
                // DIRECTORIOS DE INCLUDE (-I)
                // ==========================================
                "-I", "${fileDirname}/imgui",
                "-I", "${fileDirname}/imgui/backends",
                "-I", "${fileDirname}/glfw/include",
                "-I", "${fileDirname}/npcap-sdk/include",
                
                // ==========================================
                // DIRECTORIOS DE LIBRERÍAS (-L)
                // ==========================================
                "-L", "${fileDirname}/glfw/lib-mingw-w64",
                "-L", "${fileDirname}/npcap-sdk/lib/x64",
                
                // ==========================================
                // LIBRERÍAS A ENLAZAR (-l)
                // ==========================================
                "-lglfw3",           // GLFW
                "-lopengl32",        // OpenGL
                "-lgdi32",           // Necesario para GLFW en Windows
                "-lwpcap",           // Npcap
                "-lws2_32",          // Winsock
                "-lIPHLPAPI"         // IP Helper API
            ],
            "options": {
                "cwd": "${fileDirname}"
            },
            "problemMatcher": ["$gcc"],
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "detail": "Sniffer con ImGui + GLFW + OpenGL + Npcap"
        }
    ],
    "version": "2.0.0"
}

//en el archivo properties
  "compilerPath": "C:\\msys64\\ucrt64\\bin\\gcc.exe" CAMBIAR ESTA RUTA POR LA DEL USUARIO

LINEAS COMPLETAS:

{
    "configurations": [
        {
            "name": "Win32",
            "includePath": [
            "${workspaceFolder}/**"
            ],
            "defines": [
                "_DEBUG",
                "UNICODE",
                "_UNICODE"
            ],
            "compilerPath": "C:\\msys64\\ucrt64\\bin\\gcc.exe",
            "cStandard": "c17",
            "cppStandard": "gnu++17",
            "intelliSenseMode": "windows-gcc-x64"
        }
    ],
    "version": 4
}

