"""Çalıştırma: python -m lab --mode vulnerable   (ya da --mode secure)"""

import argparse

from . import create_app


def main():
    parser = argparse.ArgumentParser(description="OWASP mini laboratuvarı (yalnız yerel)")
    parser.add_argument("--mode", choices=["vulnerable", "secure"], default="vulnerable")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    app = create_app(secure=args.mode == "secure")
    print(f"Mod: {args.mode} -> http://127.0.0.1:{args.port}  (yalnız bu makineden erişilebilir)")
    # Bilerek yalnız 127.0.0.1: açıklı uygulama ağdaki başka makinelere görünmesin.
    app.run(host="127.0.0.1", port=args.port, debug=False)


if __name__ == "__main__":
    main()
