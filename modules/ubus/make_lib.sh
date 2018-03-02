gcc ubus_publish.c -lubox -lubus -c -o ubus_publish.o
ar rcs libubus_publish.a ubus_publish.o
