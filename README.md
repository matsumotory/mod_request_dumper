# mod_request_dumper
Dump request_rec as JSON. Dump rquest_rec to /tmp/apache_dump.log or pipe.

## Install
```
make
make install
```

## Setting to httpd.conf
- Load
```
LoadModule request_dumper_module /usr/lib/httpd/modules/mod_request_dumper.so
```

- set loggin
    - file mode
    ```
    DumpRequestLog "/tmp/apache_dump.log"
    ```

    - pipe mode
    ```
    DumpRequestLog "| mongoimport -d apache -c request_rec"
    ```

- dump hook phase
```
DumpPostReadRequest On
DumpTranslateName On
DumpMapToStorage On
DumpCheckUserId On
DumpTypeChecker On
DumpAccessChecker On
DumpAuthChecker On
DumpInsertFilter On
DumpFixups On
DumpQuickHandler On
DumpHandler On
DumpLogTransaction On
```
