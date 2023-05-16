# TLS test utils

Note: Makefile, server.crt, and server.key are used in automated testing, the remaining files are for convenience in manual verification.

You will require Python 3 to run these utils.

To standup a test server:

```
make serve
```

To test govulners against this server:

```
# without the custom cert configured (thus will fail)
make govulners-test-fail

# with the custom cert configured
make govulners-test-pass
```

To remove all temp files:

```
make clean
```
