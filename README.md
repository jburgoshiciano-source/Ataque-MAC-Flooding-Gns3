# Ataque-MAC-Flooding-Gns3

**Estudiante:**  Juan Francisco Burgos Hiciano

**Matrícula:**  2023-1981

**Asignatura:**  Seguridad en Redes

**Fecha:**  01 Junio 2026

**Link del video**: https://youtu.be/KufHSaH6Ce8


---

Descripción y Topología del Escenario

El laboratorio fue implementado en GNS3 con el propósito de simular una red corporativa básica y analizar el impacto de un ataque de MAC Flooding dentro de una infraestructura Cisco. La topología está compuesta por un router Cisco (R1) que funciona como gateway de la red, un switch Ethernet encargado de la conmutación de tráfico y un host VPCS (PC1) que representa a un usuario legítimo. Además, se incorporó un Cloud VMnet8 para proporcionar conectividad con la red del host físico. El escenario permite demostrar cómo un atacante puede inundar la tabla MAC (CAM Table) del switch mediante el envío masivo de direcciones MAC falsas, provocando que el dispositivo opere temporalmente como un hub y reenviando tráfico a múltiples puertos. Esto facilita la captura de paquetes y evidencia los riesgos asociados a la falta de mecanismos de seguridad de capa 2.


### Detalles de la Topología
* **Segmentación de Red:** Se ha configurado la **VLAN 1**
* **Direccionamiento IP:** Subred `192.168.140.0/24`.
* **Infraestructura:**
    * **Router Cisco c7200**
    * **Switch Cisco IOU L2**
* **Actores:**
    * **Atacante:** Kali Linux (IP `192.168.140.132`).
    * **Víctima:** PC1 / VPCS (IP `192.168.140.120`).

<img width="888" height="650" alt="Image" src="https://github.com/jburgoshiciano-source/DoS-mediante-el-protocolo-CDP-gns3/blob/4bd6302c763df840d1c6a647a1580aacc459e6ab/1111111.png" />

### Tabla de Direccionamiento

| Dispositivo | Dirección IP | Máscara de Subred | Gateway Predeterminado |
| :--- | :--- | :--- | :--- |
| **Router Gateway** | 192.168.140.1 | 255.255.255.0 (/24) | N/A |
| **Kali Linux (Atacante)** | 192.168.140.132 | 255.255.255.0 (/24) | 192.168.140.132 |
| **PC1 (Víctima)** | 192.168.140.120 | 255.255.255.0 (/24) | 192.168.140.1 |
---

 Requisitos Previos y Herramientas

Para la ejecución exitosa de estos scripts, se requiere el siguiente entorno:

* **Sistema Operativo:** Kali Linux o cualquier distribución Linux compatible.
* **Lenguaje:** Python 3.x.
* **Librerías:** `Scapy` (Instalación: `sudo apt install python3-scapy`).
* Simulador de Red: GNS3.
Dispositivos Simulados:
Router Cisco c7200.
Switch Cisco IOU L2.
VPCS (víctima).
Cloud VMnet8.
Permisos: Acceso de superusuario (root) para el envío de tramas Ethernet a nivel de capa 2.
Ataque Simulado: MAC Flooding.

---

 Ataque : MAC Flooding 

 ### Objetivo del Script
El script implementa una simulación de un ataque de MAC Flooding en un entorno de laboratorio controlado. Su objetivo es generar y enviar una gran cantidad de tramas Ethernet utilizando direcciones MAC de origen aleatorias con el fin de saturar la tabla CAM (Content Addressable Memory) del switch. Al agotarse la capacidad de la tabla, el switch puede dejar de asociar correctamente las direcciones MAC a sus puertos y comenzar a reenviar tráfico a múltiples interfaces, comportándose de manera similar a un hub. Esta práctica permite demostrar cómo un atacante podría facilitar la captura de tráfico de otros dispositivos de la red, comprometiendo la confidencialidad de las comunicaciones y evidenciando la importancia de implementar mecanismos de seguridad de capa 2, como Port Security, en infraestructuras de red empresariales.

### Parámetros Usados
Interfaz de red: eth0

Topología: Router Cisco c7200, Switch Cisco IOU L2, Kali Linux (Atacante), VPCS (Víctima) y Cloud VMnet8.
Red: 192.168.140.0/24

Direcciones MAC de origen: Generadas de forma aleatoria para simular múltiples dispositivos dentro de la red.

Destino de las tramas: Direcciones MAC variables enviadas a través del switch objetivo.

Herramienta utilizada: Python 3.x con Scapy.

Objetivo: Saturar la tabla CAM (Content Addressable Memory) del switch mediante el envío masivo de tramas Ethernet con direcciones MAC falsificadas.

Resultado esperado: El switch agota su capacidad de aprendizaje de direcciones MAC y comienza a reenviar tráfico a múltiples puertos, permitiendo observar el impacto de un ataque de MAC Flooding en un entorno de laboratorio controlado.

---

### Medidas de Mitigación

Para mitigar ataques de MAC Flooding, se recomienda implementar Port Security en los puertos de acceso del switch. Esta característica limita la cantidad de direcciones MAC que pueden aprenderse en una interfaz y permite definir acciones cuando se supera dicho límite. De esta manera, se evita que un atacante pueda inundar la tabla CAM del switch con direcciones MAC falsas y comprometer la confidencialidad del tráfico de la red.

```bash
Switch(config)# interface FastEthernet0/1
Switch(config-if)# switchport mode access
Switch(config-if)# switchport port-security
Switch(config-if)# switchport port-security maximum 2
Switch(config-if)# switchport port-security violation shutdown
```
Beneficios
Limita el número de direcciones MAC permitidas por puerto.
Evita la saturación de la tabla CAM del switch.
Reduce el riesgo de captura de tráfico mediante MAC Flooding.
Permite detectar y bloquear dispositivos no autorizados.
Incrementa la seguridad de la infraestructura de capa 2.
