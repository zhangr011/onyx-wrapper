"""TCP proxy: localhost:8082 -> docker_compose-keycloak-1:8082

Runs as a background process inside the API server container so that
the OIDC client can reach Keycloak via localhost:8082.
"""
import socket, threading, signal, sys


def _relay(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.send(data)
    except Exception:
        pass
    finally:
        try:
            src.close()
        except Exception:
            pass
        try:
            dst.close()
        except Exception:
            pass


def _handle(client):
    try:
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.connect(("docker_compose-keycloak-1", 8082))
        threading.Thread(target=_relay, args=(client, remote), daemon=True).start()
        threading.Thread(target=_relay, args=(remote, client), daemon=True).start()
    except Exception as e:
        print(f"Keycloak proxy connect error: {e}", file=sys.stderr)
        try:
            client.close()
        except Exception:
            pass


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 8082))
srv.listen(10)
print("Keycloak proxy listening on :8082 -> docker_compose-keycloak-1:8082", flush=True)


def _accept_loop():
    while True:
        try:
            client, _ = srv.accept()
            threading.Thread(target=_handle, args=(client,), daemon=True).start()
        except Exception:
            break


# Use a non-daemon thread for the accept loop so the process stays alive
threading.Thread(target=_accept_loop, daemon=False).start()

# Block forever in the main thread to keep the process alive
signal.pause()
