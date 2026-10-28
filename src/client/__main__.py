from pathlib import Path
import sys

from client.bootstrap.ssl_hardening import install_ssl_cert_store_fallback

install_ssl_cert_store_fallback()

from client.main import main


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--self-test":
        from client.bootstrap.self_test import run_self_test

        raise SystemExit(run_self_test(Path(sys.argv[2])))
    main()
