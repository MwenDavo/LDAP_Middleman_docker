import sys
import logging
from ftplib import MSG_OOB

import authenticator
import sender

import jwt
from jwt import InvalidTokenError
from ldap3 import Server, Connection, MODIFY_ADD, SUBTREE, MODIFY_DELETE
from pyexpat.errors import messages
from sender import *
from authenticator import *


class DataLogin:
    def __init__(self, user, password):
        self.user = user
        self.password = password

    def to_dict(self):
        return {
            'user': self.user,
            'password': self.password
        }


class DataRegister(DataLogin):
    def __init__(self, user, password, nombre, apellido, email):
        super().__init__(user, password)
        self.nombre = nombre
        self.apellido = apellido
        self.email = email

    def to_dict(self):
        return {
            'user': self.user,
            'password': self.password,
            'nombre': self.nombre,
            'apellido': self.apellido,
            'email': self.email
        }


class DataVerify:
    def __init__(self, user, module, token):
        self.user = user
        self.module = module
        self.token = token

    def to_dict(self):
        return {
            'user': self.user,
            'module': self.module,
            'token': self.token
        }


LDAP_URL = "34.196.38.176"
BASE_DN = "dc=uade,dc=edu"
SECRET = "6df1112b583b6a97435a07df12d2806223819e2a467053a6aae0181d169f390d2153b41a43890608e86144453cf8b7d5c7ff114c7b9ec405d39d6c62ffa5e8f0beca5fa2eddb3274eb3c7450fa7915e5956e985c5773c528816ec0d6ed40fa840b4f74405797fbdc2d41173ef2e6092b35aa11ef4a45cd066c70cc1e984137d93418e82de6e5be2087cd476214df7f09e8fdf362a789a08e645706ed782922782f406517082a74068fd62c4170880306224f4160cee6889c675c67ea1b087900076b43c299540ecb0067df7b2571ab07a0e4ad4dabbd0b55905fe7f2bde24cda45ed94fc1a8c2257defb1714ef01ed63f71202bd7f2219935b077319f2298d8b"

pool_connections = []

s = Server(LDAP_URL, 1389, get_info="ALL")
conn_admin = Connection(s, f"cn=uade_admin_482043,{BASE_DN}", "desarrollo_apps_2", True)

for i in range(3):
    pool_connections.append(
        start_connection('3.142.225.39',
                         '5672',
                         "autenticacion",
                         "#6@524#27Db$*96@2#^#"
                         )
    )


def handle_message(channel, method, headers, body):
    try:
        print("")
        message = convert_body(body)
        print("Mensaje recibido: " + message)
        payload = message.get('payload')
        if message['case'] == "login":
            print("Entering Login")
            print(login(payload, message['origin']))
        elif message['case'] == "register":
            print("Entering Register")
            print(register(payload, message['origin']))
    except:
        print("There was an error during the message handling")


def respond(message, module, case, token, data_type):
    publish(pool_connections[1], message, Modules.GESTION_INTERNA.value, module, case, token, data_type, "", "0","gestion_interna")


def login(dataLogin, module):
    conn = Connection(s, f"cn={dataLogin['user']},ou=people,{BASE_DN}", dataLogin['password'])
    module_name = "modulo_" + module
    if conn.bind():
        conn.search(f"{BASE_DN}", f"(&(objectClass=posixGroup)(cn={module_name}))", search_scope=SUBTREE,
                    attributes="memberUid")
        if dataLogin['user'] in conn.entries[0].memberUid.values:
            token = jwt.encode({"user": dataLogin['user'], "module": module}, SECRET, algorithm="HS256")
            print(conn_admin.result)
            print("Login token: " + token)
            respond({"status": "ok"}, module, "login", token, Types.JSON.value)
            return True
    else:
        print(conn_admin.result)
        respond({"status": "failed"}, module, "login", "", Types.JSON.value)
        return False


def register(dataRegister, module):
    if conn_admin.add(f"cn={dataRegister['user']},ou=people,{BASE_DN}", ["person", "inetOrgPerson"],
                      {'givenName': dataRegister['nombre'], 'sn': dataRegister['apellido'],
                       'mail': dataRegister['email'], 'uid': dataRegister['user'],
                       'userPassword': dataRegister['password']}):
        if conn_admin.modify('cn=everybody,ou=groups,dc=uade,dc=edu',
                             {'memberUid': [(MODIFY_ADD, [dataRegister['user']])]}) and conn_admin.modify(
            f'cn={"modulo_" + module},ou=groups,dc=uade,dc=edu',
            {'memberUid': [(MODIFY_ADD, [dataRegister['user']])]}):

            token = jwt.encode({"user": dataRegister['user'], "module": module}, SECRET, algorithm="HS256")
            print(conn_admin.result)
            print("Nuevo Token: " + token)
            respond({"status": "ok"}, module, "register", token, Types.JSON.value)
            return True
        else:
            print(conn_admin.result)
            respond({"status": "failed"}, module, "register", "", Types.JSON.value)
            return False
    else:
        print(conn_admin.result)
        respond({"status": "failed"}, module, "register", "", Types.JSON.value)
        return False


def verify(channel, method, headers, body):
    message = convert_body(body)
    try:
        decoded = jwt.decode(message['token'], SECRET, algorithms='HS256')
        print("Token: " + message['token'])
        print("Decoded token: " + str(decoded))
        if decoded:
            confirm(channel, headers, method)
    except InvalidTokenError:
        print("Rejected token: " + message['token'])
        deny(channel, headers, method)
    # if dataVerify['user'] == decoded['user'] and dataVerify['module'] == decoded['module']:
    #    respond()
    #    return True
    # else:
    #    return False


sender.callback = handle_message
authenticator.callback = verify
start_consumer(pool_connections[0], "autenticacion")
start_authenticator(pool_connections[2])

# conn_admin.delete("cn=matias,ou=people,dc=uade,dc=edu")
# conn_admin.modify('cn=everybody,ou=groups,dc=uade,dc=edu', {'memberUid': [(MODIFY_DELETE, ["matias"])]})
# conn_admin.modify(f'cn=modulo_usuario,ou=groups,dc=uade,dc=edu',{'memberUid': [(MODIFY_DELETE, ["matias"])]})
# respond(convert_class(DataRegister("user_test", "pass_test", "NameTest", "SurnameTest", "testing@uade.edu.ar")),Modules.GESTION_INTERNA.value, "Register")
# respond(convert_class(DataLogin("user_test", "pass_test")), Modules.GESTION_INTERNA.value, "Login")
