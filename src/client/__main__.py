from client.bootstrap.ssl_hardening import install_ssl_cert_store_fallback

install_ssl_cert_store_fallback()

from client.main import main


if __name__ == "__main__":
    main()
