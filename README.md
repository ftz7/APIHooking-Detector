# NT Hook Detector 🛡️

**NT Hook Detector** é uma ferramenta de linha de comando desenvolvida em C para sistemas Windows (x64), projetada para identificar **User-mode Hooks** em funções da `ntdll.dll`.

Muitas soluções de segurança, como EDRs (Endpoint Detection and Response) e Antivírus, monitoram atividades suspeitas redirecionando as chamadas das APIs nativas do Windows para seus próprios motores de análise através de uma técnica chamada *Hooking*. Este programa verifica se o prólogo original das funções `Nt*` foi alterado na memória.

---

## 🚀 Como Funciona

O programa carrega a `ntdll.dll` do processo atual, percorre sua tabela de exportação e inspeciona os primeiros bytes de cada função iniciada com o prefixo "Nt".

### Critério de Detecção
Em sistemas Windows 64 bits modernos, a grande maioria das syscalls na `ntdll` começa com a seguinte sequência de bytes (o prólogo padrão):

`4C 8B D1 B8`  ->  Representando as instruções: `mov r10, rcx; mov eax, <syscall_number>`



Se o programa detecta que esses bytes iniciais foram alterados (geralmente por uma instrução `JMP` ou `E9`), ele sinaliza que a função está sendo monitorada ou interceptada por um software externo.

---

## 🛠️ Funcionalidades

* **Varredura Dinâmica:** Analisa a `ntdll.dll` carregada em tempo de execução.
* **Detecção de Assinatura:** Compara os bytes da função com o padrão esperado de uma syscall legítima.
* **Lista de Exceções (Blacklist):** Ignora funções que não seguem o padrão de syscall, como `NtdllDialogWndProc`.
* **Tratamento Especial:** Possui lógica dedicada para funções com prólogos únicos, como `NtQuerySystemTime` e `NtGetTickCount`.
* **Log de Saída:** Exporta automaticamente os nomes das funções "hookadas" para um arquivo de texto definido pelo usuário.

---

## 💻 Compilação

Para compilar o projeto, recomenda-se o uso do **Visual Studio** com o compilador **MSVC**.

1. Abra o `Developer Command Prompt for VS`.
2. Navegue até a pasta do projeto.
3. Compile o código:
   ```bash
   cl.exe /W3 /EHsc main.cpp /link /out:nthookdetect.exe

---

## 📖 Exemplo de Uso

* **nthookdetect.exe hooks_detectados.txt

## 💻 Exemplo de saída do terminal

* **[*] NT API being hooked:
* **=========================================================================================
* **[-] NtCreateFile [0xB8D18B4C != 0xE9...]
* **[-] NtAllocateVirtualMemory [0xB8D18B4C != 0xE9...]
* **=========================================================================================
