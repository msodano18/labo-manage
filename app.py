# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired
from ping3 import ping
from flask_socketio import SocketIO
import subprocess
from datetime import datetime
import paramiko
from werkzeug.security import generate_password_hash
from cryptography.fernet import Fernet, InvalidToken
from config import SECRET_KEY_CIFRADO

app = Flask(__name__)
socketio = SocketIO(app)
app.config['SECRET_KEY'] = 'Aksa4h'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/registro-labo'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

key = SECRET_KEY_CIFRADO
cipher = Fernet(key)

class Servers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Nombre = db.Column(db.String(80), unique=True, nullable=False)
    IP = db.Column(db.String(120), unique=True, nullable=False)
    usuario_ssh = db.Column(db.String(80), nullable=True)
    contrasena_ssh = db.Column(db.String(128), nullable=True)
    last_online = db.Column(db.DateTime, nullable=True)
    last_offline = db.Column(db.DateTime, nullable=True)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class ServersForm(FlaskForm):
    Nombre = StringField('Nombre', validators=[DataRequired()])
    IP = StringField('IP', validators=[DataRequired()])
    usuario_ssh = StringField('Usuario SSH', validators=[DataRequired()])
    contrasena_ssh = PasswordField('Contraseña SSH', validators=[DataRequired()])
    submit = SubmitField('Añadir')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class UserForm(FlaskForm):
    username = StringField('Nombre de usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    submit = SubmitField('Añadir usuario')

def create_user(username, password):
    encrypted_password = cipher.encrypt(password.encode()).decode('utf-8')
    user = User(username=username, password_hash=encrypted_password)
    db.session.add(user)
    db.session.commit()

def create_default_user():
    existing_user = User.query.filter_by(username='admin').first()
    if not existing_user:
        create_user('admin', 'admin')
        print("Usuario 'admin' creado con éxito")
    else:
        print("Usuario 'admin' ya existe")

def check_ping(host):
    response_time = ping(host)
    server = Servers.query.filter_by(IP=host).first()
    if server:
        if isinstance(response_time, float):
            server.last_online = datetime.utcnow()
            db.session.commit()
            return True
        else:
            server.last_offline = datetime.utcnow()
            db.session.commit()
            return False
    return None


def ssh_connect_and_run(ip, username, encrypted_password, command):
    try:
        password = decrypt_password(encrypted_password)
    except InvalidToken:
        print(f"Error: No se pudo descifrar la contraseña para el servidor {ip}")
        return None
    except Exception as e:
        print(f"Error inesperado al descifrar la contraseña para el servidor {ip}: {e}")
        return None

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print("Conectando a {} con usuario {}".format(ip, username))
        ssh.connect(ip, username=username, password=password)
        print("Conexión SSH exitosa, ejecutando comando")
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read()
        ssh.close()
        return output
    except Exception as e:
        print(f"Error de conexión SSH: {e}")
        return None


def procesar_servicios(output):
    servicios = []
    for line in output.split('\n'):
        if '[ + ]' in line:
            estado = '⬤'
            color = 'green'
        elif '[ - ]' in line:
            estado = '⬤'
            color = 'red'
        else:
            continue
        nombre_servicio = line.split(' ')[-1]
        servicios.append({'nombre': nombre_servicio, 'estado': estado, 'color': color})
    return servicios

def obtener_interfaces(ip, username, password):
    resultado = ssh_connect_and_run(ip, username, password, 'ip addr show')
    if resultado:
        return procesar_interfaces(resultado.decode('utf-8'))
    else:
        return []

def procesar_interfaces(output):
    interfaces = []
    for line in output.split('\n'):
        if line.startswith(" "):
            continue
        partes = line.split()
        if partes and len(partes) >= 2:
            nombre_interfaz = partes[1].strip(':')
            direccion_ip = obtener_ip(output, nombre_interfaz)
            interfaces.append({'nombre': nombre_interfaz, 'ip': direccion_ip})
    return interfaces

def obtener_ip(output, interfaz):
    lineas = output.split('\n')
    for i, linea in enumerate(lineas):
        if interfaz in linea:
            for j in range(i+1, len(lineas)):
                if 'inet ' in lineas[j]:
                    partes = lineas[j].split()
                    for parte in partes:
                        if parte.startswith('inet'):
                            ip = partes[partes.index(parte) + 1].split('/')[0]
                            return ip
    return "no disponible"

def encrypt_password(password):
    encrypted = cipher.encrypt(password.encode())
    return encrypted.decode('utf-8')   

def decrypt_password(encrypted_password):
    encrypted = encrypted_password.encode('utf-8')
    decrypted = cipher.decrypt(encrypted)
    return decrypted.decode()

@socketio.on('run_command')
def handle_command(json):
    cmd = json['data']
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()
        emit('command_output', {'data': output})
    except subprocess.CalledProcessError as e:
        emit('command_output', {'data': str(e)})
    

@app.route('/home', methods=['GET', 'POST'])
def index():
    form = ServersForm()
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder a esta página.')
        return redirect(url_for('login'))
    if form.validate_on_submit():
        encrypted_password = encrypt_password(form.contrasena_ssh.data)
        server = Servers(Nombre=form.Nombre.data, IP=form.IP.data, usuario_ssh=form.usuario_ssh.data, contrasena_ssh=encrypted_password)
        db.session.add(server)
        db.session.commit()
        flash('Servidor añadido con éxito!', 'success')
        return redirect(url_for('index'))

    servers = Servers.query.all()
    
    total_servers = len(servers)
    servers_on = 0
    servers_off = 0
    servidores_con_espacio_lleno = []

    for server in servers:
        if check_ping(server.IP):
            servers_on += 1
            espacio_porcentaje_usado = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'df -h | grep \' /$\' | awk \'{print $5}\' | tr -d \'%\'')
            if espacio_porcentaje_usado:
                espacio_porcentaje_usado = espacio_porcentaje_usado.decode('utf-8').strip()
                if espacio_porcentaje_usado and float(espacio_porcentaje_usado) > 90:
                    servidores_con_espacio_lleno.append(server.Nombre)
        else:
            servers_off += 1

        server.ping_status = check_ping(server.IP)
        db.session.commit()

    ping_statuses = {server.Nombre: server.ping_status for server in servers}

    return render_template('index.html', form=form, servers=servers, ping_statuses=ping_statuses, total_servers=total_servers, servers_on=servers_on, servers_off=servers_off, servidores_con_espacio_lleno=servidores_con_espacio_lleno)




@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and cipher.decrypt(user.password_hash.encode('utf-8')).decode() == form.password.data:
            session['user_id'] = user.id
            flash('Has iniciado sesión con éxito!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Usuario o contraseña incorrectos', 'danger')
    return render_template('login.html', form=form)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder a esta página.', 'warning')
        return redirect(url_for('login'))
    form = UserForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        encrypted_password = encrypt_password(password) 
        user = User(username=username, password_hash=encrypted_password)
        db.session.add(user)
        db.session.commit()
        flash('Usuario añadido con éxito', 'success')
        return redirect(url_for('settings'))

    users = User.query.all()
    return render_template('settings.html', form=form, users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('Usuario eliminado con éxito', 'success')
    return redirect(url_for('settings'))



@app.route('/edit/<int:server_id>', methods=['POST'])
def edit_server(server_id):
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder a esta página.')
        return redirect(url_for('login'))
    data = request.get_json()
    server = Servers.query.get_or_404(server_id)

    server.Nombre = data['Nombre']
    server.IP = data['IP']
    server.usuario_ssh = data['usuario_ssh']
    if 'contrasena_ssh' in data and data['contrasena_ssh']:
        encrypted_password = cipher.encrypt(data['contrasena_ssh'].encode())
        server.contrasena_ssh = encrypted_password.decode('utf-8')

    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Servidor actualizado con éxito'})


@app.route('/delete/<int:servers_id>', methods=['POST'])
def delete_server(servers_id):
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder a esta página.')
        return redirect(url_for('login'))
    servers = Servers.query.get(servers_id)
    if servers:
        db.session.delete(servers)
        db.session.commit()
        flash('Servidor eliminado con éxito!', 'success')
    else:
        flash('Servidor no encontrado!', 'danger')
    return redirect(url_for('index'))

@app.route('/run_iperf_test', methods=['POST'])
def run_iperf_test():
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Debes iniciar sesión para acceder a esta página.'})
    
    data = request.get_json()
    server_left_id = data.get('server_left')
    server_right_id = data.get('server_right')
    
    server_left = Servers.query.get(server_left_id)
    server_right = Servers.query.get(server_right_id)
    
    if not server_left or not server_right:
        return jsonify({'status': 'error', 'message': 'Servidor no encontrado.'})

    start_iperf_command = 'iperf3 -s -p 6000 &'
    result_left = ssh_connect_and_run(server_left.IP, server_left.usuario_ssh, server_left.contrasena_ssh, start_iperf_command)
    if result_left is None:
        return jsonify({'status': 'error', 'message': 'Error al iniciar iperf3 en el servidor de la izquierda.'})
    
    iperf_test_command = f'iperf3 -c {server_left.IP} -p 6000 | grep "receiver" | awk \'{{print $7, $8}}\''
    result_right = ssh_connect_and_run(server_right.IP, server_right.usuario_ssh, server_right.contrasena_ssh, iperf_test_command)
    if result_right is None:
        return jsonify({'status': 'error', 'message': 'Error al ejecutar iperf3 en el servidor de la derecha.'})
    
    avg_speed = result_right.decode('utf-8').strip()

    if avg_speed:
        avg_speed = f'{avg_speed}'
    else:
        avg_speed = 'No se pudo determinar la velocidad.'

    return jsonify({'status': 'success', 'result': avg_speed})



@app.route('/details/<int:servers_id>', methods=['GET', 'POST'])
def server_details(servers_id):
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder a esta página.')
        return redirect(url_for('login'))
    server = Servers.query.get(servers_id)
    form = ServersForm()

    if form.validate_on_submit():
        encrypted_password = encrypt_password(form.contrasena_ssh.data)
        new_server = Servers(
            Nombre=form.Nombre.data, 
            IP=form.IP.data, 
            usuario_ssh=form.usuario_ssh.data,
            contrasena_ssh=encrypted_password
        )
        db.session.add(new_server)
        db.session.commit()
        flash('Servidor añadido con éxito!', 'success')
        return redirect(url_for('server_details', servers_id=servers_id))

    servers = Servers.query.all()
    ping_statuses = {server.Nombre: check_ping(server.IP) for server in servers}

    if not check_ping(server.IP):
        return render_template('error.html', server=server, form=form, ping_statuses=ping_statuses, servers=servers) 

    if server:
        sistemaOperativo = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'lsb_release -a')
        if sistemaOperativo is not None:
            sistemaOperativo = sistemaOperativo.decode('utf-8').strip()
        else:
            sistemaOperativo = "Error al conectar con el servidor o ejecutar el comando."

        servicios_output = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'service --status-all')
        if servicios_output is not None:
            servicios = procesar_servicios(servicios_output.decode('utf-8'))
        else:
            servicios = "Error al conectar con el servidor o ejecutar el comando."

        interfaces = obtener_interfaces(server.IP, server.usuario_ssh, server.contrasena_ssh)

        espacio_total = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'df -h | grep \' /$\' | awk -F\' \' \'{print $2}\'')
        if espacio_total is not None:
            espacio_total = espacio_total.decode('utf-8').strip()
        else:
            espacio_total = "Información no disponible..."

        espacio_free = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'df -h | grep \' /$\' | awk -F\' \' \'{print $4}\'')
        if espacio_free is not None:
            espacio_free = espacio_free.decode('utf-8').strip()
        else:
            espacio_total = "Información no disponible..."

        espacio_usado = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'df -h | grep \' /$\' | awk -F\' \' \'{print $3}\'')
        if espacio_usado is not None:
            espacio_usado = espacio_usado.decode('utf-8').strip()
        else:
            espacio_usado = "Información no disponible..."

        espacio_porcentaje_usado = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'df -h | grep \' /$\' | awk -F\' \' \'{print $5}\' | tr -d \'%\'')
        if espacio_porcentaje_usado is not None:
            espacio_porcentaje_num = float(espacio_porcentaje_usado)
            espacio_porcentaje_usado = espacio_porcentaje_usado.decode('utf-8').strip()
        else:
            espacio_porcentaje_usado = "Información no disponible..."

        nombre_servidor = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'hostname')
        if nombre_servidor:
            nombre_servidor = nombre_servidor.decode('utf-8').strip()
            if not nombre_servidor:
                nombre_servidor = "Información no disponible..."
        else:
            nombre_servidor = "Información no disponible..."

        marca_servidor = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo dmidecode | grep -A 5 "System Information" | grep -i "Manufacturer" | awk -F\': \' \'{print $2}\'')
        if marca_servidor:
            marca_servidor = marca_servidor.decode('utf-8').strip()
            if not marca_servidor:
                marca_servidor = "Información no disponible..."
        else:
            marca_servidor = "Información no disponible..."

        modelo_servidor = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo dmidecode | grep -A 5 "System Information" | grep -i "Product Name" | awk -F\': \' \'{print $2}\'')
        if modelo_servidor:
            modelo_servidor = modelo_servidor.decode('utf-8').strip()
            if not modelo_servidor:
                modelo_servidor = "Información no disponible..."
        else:
            modelo_servidor = "Información no disponible..."

        bios_version = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo dmidecode | grep -A 5 "BIOS Information" | grep -i "version" | awk -F\': \' \'{print $2}\'')
        if bios_version:
            bios_version = bios_version.decode('utf-8').strip()
            if not bios_version:
                bios_version = "Información no disponible..."
        else:
            bios_version = "Información no disponible..."

        cpu_name = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo cat /proc/cpuinfo | grep -i "model name" | awk -F\': \' \'{print $2}\' | head -n 1')
        if cpu_name:
            cpu_name = cpu_name.decode('utf-8').strip()
            if not cpu_name:
                cpu_name = "Información no disponible..."
        else:
            cpu_name = "Información no disponible..."

        cpu_cores = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo cat /proc/cpuinfo | grep -i "model name" | awk -F\': \' \'{print $2}\' | wc -l')
        if cpu_cores:
            cpu_cores = cpu_cores.decode('utf-8').strip()
            if not cpu_cores or not cpu_cores.isdigit():
                cpu_cores = "Información no disponible..."
        else:
            cpu_cores = "Información no disponible..."

        gpu_name = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'lspci | grep VGA | awk -F\': \' \'{print $2}\' | awk -F\' [(]\' \'{print $1}\'')
        if gpu_name:
            gpu_name = gpu_name.decode('utf-8').strip()
            if not gpu_name:
                gpu_name = "Información no disponible..."
        else:
            gpu_name = "Información no disponible..."

        ram_type = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo dmidecode | grep -A 15 "Memory Device$" | grep -i "Type:" | awk -F\': \' \'{print $2}\' | head -n 1')
        if ram_type:
            ram_type = ram_type.decode('utf-8').strip()
            if not ram_type:  
                ram_type = "Información no disponible..."
        else:
            ram_type = "Información no disponible..."

        ram_cap = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo free --giga -h | grep -i "Mem" | awk -F\' \' \'{print $2}\'')
        if ram_cap:
            ram_cap = ram_cap.decode('utf-8').strip()
            if not ram_cap:
                ram_cap = "Información no disponible..."
        else:
            ram_cap = "Información no disponible..."

        ram_in_use = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, ' sudo free --giga -h | grep -i "Mem" | awk -F\' \' \'{print $3}\'')
        if ram_in_use:
            ram_in_use = ram_in_use.decode('utf-8').strip()
            if not ram_in_use:
                ram_in_use = "Información no disponible..."
        else:
            ram_in_use = "Información no disponible..."

        ram_free = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo free --giga -h | grep -i "Mem" | awk -F\' \' \'{print $4}\'')
        if ram_free:
            ram_free = ram_free.decode('utf-8').strip()
            if not ram_free:
                ram_free = "Información no disponible..."
        else:
            ram_free = "Información no disponible..."

        mboard_name = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo dmidecode | grep -A 5 "Base Board Information" | grep -i "Manufacturer" | awk -F\': \' \'{print $2}\'')
        if mboard_name:
            mboard_name = mboard_name.decode('utf-8').strip()
            if not mboard_name:
                mboard_name = "Información no disponible..."
        else:
            mboard_name = "Información no disponible..."

        mboard_model = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo dmidecode | grep -A 5 "Base Board Information" | grep -i "Product Name" | awk -F\': \' \'{print $2}\'')
        if mboard_model:
            mboard_model = mboard_model.decode('utf-8').strip()
            if not mboard_model:
                mboard_model = "Información no disponible..."
        else:
            mboard_model = "Información no disponible..."

        ventilation_type = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo dmidecode | grep -A 5 "Cooling Device" | grep -i "type" | awk -F\': \' \'{print $2}\'')
        if ventilation_type:
            ventilation_type = ventilation_type.decode('utf-8').strip()
            if not ventilation_type:
                ventilation_type = "Información no disponible..."
        else:
            ventilation_type = "Información no disponible..."

        programmed_speed = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo dmidecode | grep -A 5 "Cooling Device" | grep -i "nominal speed" | awk -F\': \' \'{print $2}\'')
        if programmed_speed:
            programmed_speed = programmed_speed.decode('utf-8').strip()
            if not programmed_speed:
                programmed_speed = "Información no disponible..."
        else:
            programmed_speed = "Información no disponible..."

        ventilation_status = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo dmidecode | grep -A 5 "Cooling Device" | grep -i "status" | awk -F\': \' \'{print $2}\'')
        if ventilation_status:
            ventilation_status = ventilation_status.decode('utf-8').strip()
            if not ventilation_status:
                ventilation_status = "Información no disponible..."
        else:
            ventilation_status = "Información no disponible..."


        return render_template(
            'details.html', 
            server=server, 
            form=form, 
            servers=servers, 
            ping_statuses=ping_statuses,
            sistemaOperativo=sistemaOperativo,
            servicios=servicios,
            interfaces=interfaces,
            nombre_servidor=nombre_servidor,
            marca_servidor=marca_servidor,
            modelo_servidor=modelo_servidor,
            bios_version=bios_version,
            cpu_name=cpu_name,
            cpu_cores=cpu_cores,
            gpu_name=gpu_name,
            ram_type=ram_type,
            ram_cap=ram_cap,
            ram_in_use=ram_in_use,
            ram_free=ram_free,
            mboard_name=mboard_name,
            mboard_model=mboard_model,
            ventilation_type=ventilation_type,
            programmed_speed=programmed_speed,
            ventilation_status=ventilation_status,
            espacio_total=espacio_total,
            espacio_free=espacio_free,
            espacio_usado=espacio_usado,
            espacio_porcentaje_usado=espacio_porcentaje_usado,
            espacio_porcentaje_num=espacio_porcentaje_num
        )

@app.route('/manage_service/<int:servers_id>/<string:service>/<string:action>', methods=['POST'])
def manage_service(servers_id, service, action):
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder a esta página.')
        return redirect(url_for('login'))
    server = Servers.query.get(servers_id)
    if server:
        comando = f"sudo /etc/init.d/{service} {action}"
        resultado = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, comando)
        if resultado is not None:
            return jsonify({'status': 'success', 'output': resultado.decode('utf-8')})
        else:
            return jsonify({'status': 'error', 'message': 'No se pudo ejecutar el comando.'})
    else:
        return jsonify({'status': 'error', 'message': 'Servidor no encontrado.'})

@app.route('/change_ip/<int:server_id>/<string:interface>/<string:new_ip>', methods=['POST'])
def change_ip(server_id, interface, new_ip):
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder a esta página.')
        return redirect(url_for('login'))
    server = Servers.query.get(server_id)
    if not server:
        return jsonify({'status': 'error', 'message': 'Servidor no encontrado'})

    comando = f"sudo ifconfig {interface} {new_ip} netmask 255.255.255.0 up"
    resultado = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, comando)
    
    if resultado is not None:
        return jsonify({'status': 'success', 'message': 'Dirección IP cambiada con éxito. Se aconseja reiniciar el servidor...'})
    else:
        return jsonify({'status': 'error', 'message': 'Error al cambiar la dirección IP'})

@app.route('/change_interface_name/<int:server_id>/<string:interface>/<string:new_interface_name>', methods=['POST'])
def change_interface_name(server_id, interface, new_interface_name):
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder a esta página.')
        return redirect(url_for('login'))
    server = Servers.query.get(server_id)
    if not server:
        return jsonify({'status': 'error', 'message': 'Servidor no encontrado'})

    comando = f"sudo ip link set {interface} name {new_interface_name}"
    resultado = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, comando)
    
    if resultado is not None:
        return jsonify({'status': 'success', 'message': 'Nombre de la interfaz actualizada con éxito! Se aconseja reiniciar el servidor...'})
    else:
        return jsonify({'status': 'error', 'message': 'Error al cambiar el nombre de la intefaz'})

@app.route('/shutdown/<int:server_id>', methods=['POST'])
def shutdown_server(server_id): 
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder a esta página.')
        return redirect(url_for('login'))
    server = Servers.query.get(server_id)
    if server:
        resultado = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo shutdown now')
        if resultado:
            return jsonify({'status': 'success', 'message': 'Servidor apagado'})
        else:
            return jsonify({'status': 'error', 'message': 'Error al ejecutar el comando de apagado'})
    else:
        return jsonify({'status': 'error', 'message': 'Servidor no encontrado'})

@app.route('/reboot/<int:server_id>', methods=['POST'])
def reboot_server(server_id):
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder a esta página.')
        return redirect(url_for('login'))
    server = Servers.query.get(server_id)
    if server:
        resultado = ssh_connect_and_run(server.IP, server.usuario_ssh, server.contrasena_ssh, 'sudo reboot')
    else:
        return jsonify({'status': 'error', 'message': 'Servidor no encontrado'})

if __name__ == "__main__":
    with app.app_context():
        create_default_user()
    app.run(debug=True, host='0.0.0.0')
