import atexit

import authenticator

import jwt
from ldap3 import Server, Connection, MODIFY_ADD, SUBTREE
from sender import *
from authenticator import *

LDAP_URL = "34.196.38.176"
BASE_DN = "dc=uade,dc=edu"
SECRET = "6df1112b583b6a97435a07df12d2806223819e2a467053a6aae0181d169f390d2153b41a43890608e86144453cf8b7d5c7ff114c7b9ec405d39d6c62ffa5e8f0beca5fa2eddb3274eb3c7450fa7915e5956e985c5773c528816ec0d6ed40fa840b4f74405797fbdc2d41173ef2e6092b35aa11ef4a45cd066c70cc1e984137d93418e82de6e5be2087cd476214df7f09e8fdf362a789a08e645706ed782922782f406517082a74068fd62c4170880306224f4160cee6889c675c67ea1b087900076b43c299540ecb0067df7b2571ab07a0e4ad4dabbd0b55905fe7f2bde24cda45ed94fc1a8c2257defb1714ef01ed63f71202bd7f2219935b077319f2298d8b"

pool_connections = []

s = Server(LDAP_URL, 1389, get_info="ALL")
conn_admin = Connection(s, f"cn=uade_admin_482043,{BASE_DN}", "desarrollo_apps_2", True)

for i in range(1):
    pool_connections.append(
        start_connection('3.142.225.39',
                         '5672',
                         "gestion_interna",
                         "&%2427L5&#$#3d@458*$"
                         )
    )


def handle_message(channel, method, headers, body):
    try:
        print("\n\n NEW MESSAGE")
        message = convert_body(body)
        print("Mensaje recibido: ", message)
        if message.get('case') == "login":
            print("Entering Login")
            token = login(message.get('user'), message.get('password'), message.get('origin'))
            if token:
                confirm(channel, method, headers, token)
            else:
                deny(channel, method, headers)
        elif message.get('case') == "register":
            print("Entering Register")
            token = register(message.get('user'), message.get('password'), message.get('nombre'),
                             message.get('apellido'), message.get('email'), message.get('origin'))
            if token:
                confirm(channel, method, headers, token)
            else:
                deny(channel, method, headers)
        elif message.get('case') == "verify":
            print("Entering Verify")
            status = verify(message.get('token'))
            if status:
                confirm(channel, method, headers, str(status))
            else:
                deny(channel, method, headers)
    except Exception as e:
        print("ERROR!!!")
        print(e)
        deny(channel, method, headers)


def login(user, password, module):
    conn = Connection(s, f"uid={user},ou=people,{BASE_DN}", password)
    module_name = "modulo_" + module
    if conn.bind():
        conn.search(f"{BASE_DN}", f"(&(objectClass=posixGroup)(cn={module_name}))", search_scope=SUBTREE,
                    attributes="memberUid")
        if user in conn.entries[0].memberUid.values:
            token = jwt.encode({"user": user, "module": module}, SECRET, algorithm="HS256")
            print(conn_admin.result)
            print("Nuevo Token: " + token)
            return token
    else:
        print("ERROR!!!")
        print(conn.result)
        return None


def register(user, password, nombre, apellido, email, module):
    cn = (nombre + apellido).replace(" ", "")
    if conn_admin.add(f"uid={user},ou=people,{BASE_DN}", ["person", "inetOrgPerson"],
                      {'cn': cn, 'givenName': nombre, 'sn': apellido,
                       'mail': email, 'uid': user,
                       'userPassword': password}):
        if conn_admin.modify('cn=everybody,ou=groups,dc=uade,dc=edu',
                             {'memberUid': [(MODIFY_ADD, [user])]}) and conn_admin.modify(
            f'cn={"modulo_" + module},ou=groups,dc=uade,dc=edu',
            {'memberUid': [(MODIFY_ADD, [user])]}):

            token = jwt.encode({"user": user, "module": module}, SECRET, algorithm="HS256")
            print(conn_admin.result)
            print("Nuevo Token: " + token)
            return token
        else:
            print("ERROR!!!")
            print(conn_admin.result)
            return None
    else:
        print("ERROR!!!")
        print(conn_admin.result)
        return None


def verify(token):
    try:
        decoded = jwt.decode(token, SECRET, algorithms='HS256')
        print("Token: " + token)
        print("Decoded token: " + str(decoded))
        if decoded:
            return True
    except Exception as e:
        print("Rejected token: ", token)
        print("ERROR!!!")
        print(e)
        return False


def shutdown():
    close_connection(pool_connections[0])


atexit.register(shutdown)
authenticator.callback = handle_message
start_authenticator(pool_connections[0])

# conn_admin.delete("cn=matias,ou=people,dc=uade,dc=edu")
# conn_admin.modify('cn=everybody,ou=groups,dc=uade,dc=edu', {'memberUid': [(MODIFY_DELETE, ["matias"])]})
# conn_admin.modify(f'cn=modulo_usuario,ou=groups,dc=uade,dc=edu',{'memberUid': [(MODIFY_DELETE, ["matias"])]})
# respond(convert_class(DataRegister("user_test", "pass_test", "NameTest", "SurnameTest", "testing@uade.edu.ar")),Modules.GESTION_INTERNA.value, "Register")
# respond(convert_class(DataLogin("user_test", "pass_test")), Modules.GESTION_INTERNA.value, "Login")
