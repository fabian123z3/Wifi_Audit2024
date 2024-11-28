Bienvenido al auditorios de redes wifi

-el primero paso es usar kali linux usando vmware
-al tener inicializada la maquina, se conecta la antena y se selecciona la conexion hacia la maquina virtual
-usando el comando git clone https://github.com/fabian123z3/Wifi_Audit2024/  se clonara el repositorio con las carpetas guardadas
-en la carpeta src es importante abrir la terminal en ese ruta, y escribir el comando "sudo python app.py" se ejecuta el flask y en la pagina
se debe entrar a la opcion de audit panel, donde automaticamente se activa como monitor la antena

pasos para la automatizacion:

1.- Escanear redes wifi buscando el objetivo en la tabla
2.- en la seccion de captura del handshake se colocara el bssid que se muestra en la tabla junto con el canal
3.- para parar la captura del handshake , se vuelve a la consola y luego de capturar la red, se apreta la tecla Control + C
4.- el siguiente paso es volver a iniciar el archivo app.py, donde en la seccion de crackear contraseña se elege la captura anterior junto con el diccionario 
con contraseñas usadas
