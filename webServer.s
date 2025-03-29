section .data
    AF_INET     equ 2
    SOCK_STREAM equ 1
    IPPROTO_TCP equ 6
    
    port        dw 443
    backlog     dd 10
    
    server_start_msg db "HTTPS server starting on port 443...", 10, 0
    server_start_len equ $ - server_start_msg
    
    conn_msg    db "Connection received", 10, 0
    conn_len    equ $ - conn_msg
    
    cert_file   db "server.crt", 0
    key_file    db "server.key", 0
    
    http_response db "HTTP/1.1 200 OK", 13, 10
                  db "Content-Type: text/html", 13, 10
                  db "Connection: close", 13, 10, 13, 10
                  db "<html><body><h1>Secure Server</h1>"
                  db "<p>This page is served over HTTPS using x64 assembly!</p>"
                  db "</body></html>", 13, 10, 0
    
section .bss
    server_fd   resq 1
    client_fd   resq 1
    client_addr resb 16
    client_len  resd 1
    
    ssl_ctx     resq 1
    ssl_conn    resq 1
    buffer      resb 1024

section .text
global _start

extern socket, bind, listen, accept, close, send, recv
extern SSL_library_init, SSL_load_error_strings, OpenSSL_add_all_algorithms
extern SSL_CTX_new, TLS_server_method, SSL_CTX_use_certificate_file, SSL_CTX_use_PrivateKey_file
extern SSL_new, SSL_set_fd, SSL_accept, SSL_read, SSL_write, SSL_shutdown, SSL_free, SSL_CTX_free

_start:
    call SSL_library_init
    call SSL_load_error_strings
    call OpenSSL_add_all_algorithms
    
    mov rax, 1
    mov rdi, 1
    mov rsi, server_start_msg
    mov rdx, server_start_len
    syscall
    
    call TLS_server_method
    mov rdi, rax
    call SSL_CTX_new
    mov [ssl_ctx], rax
    
    mov rdi, [ssl_ctx]
    mov rsi, cert_file
    mov rdx, 1
    call SSL_CTX_use_certificate_file
    
    mov rdi, [ssl_ctx]
    mov rsi, key_file
    mov rdx, 1
    call SSL_CTX_use_PrivateKey_file
    
    mov rdi, AF_INET
    mov rsi, SOCK_STREAM
    mov rdx, IPPROTO_TCP
    call socket
    mov [server_fd], rax
    
    sub rsp, 16
    mov word [rsp], AF_INET
    mov word [rsp+2], [port]
    mov dword [rsp+4], 0
    
    mov rdi, [server_fd]
    mov rsi, rsp
    mov rdx, 16
    call bind
    
    mov rdi, [server_fd]
    mov rsi, [backlog]
    call listen
    
main_loop:
    mov rdi, [server_fd]
    mov rsi, client_addr
    mov rdx, client_len
    call accept
    mov [client_fd], rax
    
    mov rax, 1
    mov rdi, 1
    mov rsi, conn_msg
    mov rdx, conn_len
    syscall
    
    mov rdi, [ssl_ctx]
    call SSL_new
    mov [ssl_conn], rax
    
    mov rdi, [ssl_conn]
    mov rsi, [client_fd]
    call SSL_set_fd
    
    mov rdi, [ssl_conn]
    call SSL_accept
    
    mov rdi, [ssl_conn]
    mov rsi, buffer
    mov rdx, 1024
    call SSL_read
    
    mov rdi, [ssl_conn]
    mov rsi, http_response
    mov rdx, 0
    
    push rdi
    push rsi
    mov rdi, rsi
    xor rcx, rcx
strlen_loop:
    cmp byte [rdi], 0
    je strlen_end
    inc rcx
    inc rdi
    jmp strlen_loop
strlen_end:
    mov rdx, rcx
    pop rsi
    pop rdi
    
    call SSL_write
    
    mov rdi, [ssl_conn]
    call SSL_shutdown
    
    mov rdi, [ssl_conn]
    call SSL_free
    
    mov rdi, [client_fd]
    call close
    
    jmp main_loop
    
cleanup:
    mov rdi, [ssl_ctx]
    call SSL_CTX_free
    
    mov rdi, [server_fd]
    call close
    
    mov rax, 60
    xor rdi, rdi
    syscall