# escaner de puerto

#argparse generara automaticamente mensajes de ayuda y de uso de nuestros errores cuando los usuarios dan parametros incorrectos al programa "-h" este comando
#nos brindara ayuda
import argparse
#biblioteca de Python que admite expresiones regulares.
import re
import scapy.all as scapy

#importacion de la libreria scapy
from scapy.all import *






# formato de salida
def print_ports(port, state):
	print("%s | %s" % (port, state))





# scanneo tipo SYN
def syn_scan(target, ports):
	print("syn escaneo encendido, %s puertos con %s" % (target, ports))
	sport = RandShort()
	for port in ports:
		pkt = sr1(IP(dst=target)/TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)
		if pkt != None:
			if pkt.haslayer(TCP):
				if pkt[TCP].flags == 20:
					print_ports(port, "cerrado")
				elif pkt[TCP].flags == 18:
					print_ports(port, "abierto/http/Este puerto es el que se usa para la navegación web de forma no segura HTTP")
				else:
					print_ports(port, "TCP paquete respuesta / filtrado")
			elif pkt.haslayer(ICMP):
				print_ports(port, "ICMP respuesta / filtrado")
			else:
				print_ports(port, "respuesta desconocida")
				print(pkt.summary())
		else:
			print_ports(port, "sin respuesta/telnet/Telnet,sirve para establecer conexión remotamente con otro equipo por la línea de comandos y controlarlo. Es un protocolo no seguro ya que la autenticación y todo el tráfico de datos se envía sin cifrar")




# configuracion de argumento
parser = argparse.ArgumentParser("escaneo de puertos usando scapy")

#busqueda de dirreciones ip para 192.168.1.1/24
parser.add_argument("-i", "--arp_result", help="Busqueda de dirreciones ip", required=True)		

#guia de puertos tcp
parser.add_argument("-g", "--guiports", type=int,help="Especificar puertos (21 22 23 25 53 80 101 143 443)")

parser.add_argument("-t", "--target", help="Especificar IP de destino", required=True)
parser.add_argument("-p", "--ports", type=int, nargs="+",help="Especificar puertos (21 22 23 25 53 80 101 143 443 445 ...)")
parser.add_argument("-s", "--scantype",help="Tipo de escaneo, syn", required=True)

args = parser.parse_args()

#diccuonarioGuia=    {
#  "21": "este puerto se usa para el protocolo FTP que permite intercambiar archivos entre hosts",
#  "22": "este puerto se usa para el protocolo SSH ........ ",
#  "23": "este puerto se usapara el protocolo telenet....... "
#}
#print(diccionarioGuia["22"])

# arg parsing
target = args.target
scantype = args.scantype.lower()
# set ports if passed
if args.ports:
	ports = args.ports
else:
	# default port range
	ports = range(1, 1024)

# tipos de escaneo
if scantype == "syn" or scantype == "s":
	syn_scan(target, ports)
else:
	print("escaneo no permitido")	


#busqueda de puertos ip deacuerdo al rango
ip_add_range_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")
# obtener el rango para arp(protocolo de resoluciones de dirreciones)
while True:
    ip_add_range_entered = input("\nip por defecto 192.168.x.x/xx,guia de puertos): ")
    if ip_add_range_pattern.search(ip_add_range_entered):
        print(f"{ip_add_range_entered} rango de ip validos,puertos principales TCP")
        print("---------------------Guia de puertos tcp---------------------------------------------------------------------------------")
        print("")
        print("""Puerto 21: El puerto 21 por norma general se usa para las conexiones a servidores FTP en su canal de control, siempre que no hayamos cambiado el puerto de escucha de nuestro servidor FTP o FTPES.
Puerto 22: Por normal general este puerto se usa para conexiones seguras SSH y SFTP, siempre que no hayamos cambiado el puerto de escucha de nuestro servidor SSH.
Puerto 23: Telnet, sirve para establecer conexión remotamente con otro equipo por la línea de comandos y controlarlo. Es un protocolo no seguro ya que la autenticación y todo el tráfico de datos se envía sin cifrar.
Puerto 25: El puerto 25 es usado por el protocolo SMTP para él envió de correos electrónicos, también el mismo protocolo puede usar los puertos 26 y 2525.
Puerto 53: Es usado por el servicio de DNS, Domain Name System.
Puerto 80: Este puerto es el que se usa para la navegación web de forma no segura HTTP.
Puerto 101: Este puerto es usado por el servicio Hostname y sirve para identificar el nombre de los equipos.
Puerto 110: Este puerto lo usan los gestores de correo electrónico para establecer conexión con el protocolo POP3.
Puerto 143: El puerto 143 lo usa el protocolo IMAP que es también usado por los gestores de correo electrónico.
Puerto 443: Este puerto es también para la navegación web, pero en este caso usa el protocolo HTTPS que es seguro y utiliza el protocolo TLS por debajo.
Puerto 445: Este puerto es compartido por varios servicios, entre el más importante es el Active Directory.
Puerto 587: Este puerto lo usa el protocolo SMTP SSL y, al igual que el puerto anterior sirve para el envío de correos electrónicos, pero en este caso de forma segura.
Puerto 591: Es usado por Filemaker en alternativa al puerto 80 HTTP.
Puerto 853: Es utilizado por DNS over TLS.
Puerto 990: Si utilizamos FTPS (FTP Implícito) utilizaremos el puerto por defecto 990, aunque se puede cambiar.
Puerto 993: El puerto 993 lo usa el protocolo IMAP SSL que es también usado por los gestores de correo electrónico para establecer la conexión de forma segura.
Puerto 995: Al igual que el anterior puerto, sirve para que los gestores de correo electrónico establezcan conexión segura con el protocolo POP3 SSL.
Puerto 1194: Este puerto está tanto en TCP como en UDP, es utilizado por el popular protocolo OpenVPN para las redes privadas virtuales.
Puerto 1723: Es usado por el protocolo de VPN PPTP.
Puerto 1812: se utiliza tanto con TCP como con UDP, y sirve para autenticar clientes en un servidor RADIUS.
Puerto 1813: se utiliza tanto con TCP como con UDP, y sirve para el accounting en un servidor RADIUS.
Puerto 2049: es utilizado por el protocolo NFS para el intercambio de ficheros en red local o en Internet.
Puertos 2082 y 2083: es utilizado por el popular CMS cPanel para la gestión de servidores y servicios, dependiendo de si se usa HTTP o HTTPS, se utiliza uno u otro.
Puerto 3074: Lo usa el servicio online de videojuegos de Microsoft Xbox Live.
Puerto 3306: Puerto usado por las bases de datos MySQL.
Puerto 3389: Es el puerto que usa el escritorio remoto de Windows, muy recomendable cambiarlo.
Puerto 4662 TCP y 4672 UDP: Estos puertos los usa el mítico programa eMule, que es un programa para descargar todo tipo de archivos.
Puerto 4899: Este puerto lo usa Radmin, que es un programa para controlar remotamente equipos.
Puerto 5000: es el puerto de control del popular protocolo UPnP, y que por defecto, siempre deberíamos desactivarlo en el router para no tener ningún problema de seguridad.
Puertos 5400, 5500, 5600, 5700, 5800 y 5900: Son usados por el programa VNC, que también sirve para controlar equipos remotamente.
Puertos 6881 y 6969: Son usados por el programa BitTorrent, que sirve para e intercambio de ficheros.
Puerto 8080: es el puerto alternativo al puerto 80 TCP para servidores web, normalmente se utiliza este puerto en pruebas.""")
        print("")
        print("----------------------------Fin de la guia de puertos----------------------------------------------------------------------------")       
        break
#buscar dispositivos en la red        
arp_result = arping(ip_add_range_entered)