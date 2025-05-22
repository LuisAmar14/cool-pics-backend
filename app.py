import os
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from PIL import Image as PILImage
import colorsys
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError, DataError
import bleach
import pytz

# Cargar variables de entorno
load_dotenv()

# Inicializar SQLAlchemy y JWTManager
db = SQLAlchemy()
jwt = JWTManager()

# Configurar zona horaria CST (America/Mexico_City)
cst_tz = pytz.timezone('America/Mexico_City')

# Modelos
class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Palette(db.Model):
    __tablename__ = 'palettes'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(cst_tz))
    colors = db.relationship('PaletteColor', backref='palette', lazy=True, cascade='all, delete-orphan')

class PaletteColor(db.Model):
    __tablename__ = 'palette_colors'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    palette_id = db.Column(db.Integer, db.ForeignKey('palettes.id'), nullable=False)
    rgb = db.Column(db.String(20), nullable=False)
    hex = db.Column(db.String(7), nullable=False)
    hsl = db.Column(db.String(20), nullable=False)
    position = db.Column(db.Integer, nullable=False)

class Color(db.Model):
    __tablename__ = 'colors'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    rgb = db.Column(db.String(20), nullable=False)
    hex = db.Column(db.String(7), nullable=False)
    hsl = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(cst_tz))

def create_app(test_config=None):
    app = Flask(__name__)

    # Configuración por defecto
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["ALLOWED_EXTENSIONS"] = {"png", "jpg", "jpeg"}
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # Límite de 5MB

    if test_config is None:
        mysql_user = os.getenv("MYSQL_USER")
        mysql_password = os.getenv("MYSQL_PASSWORD")
        mysql_host = os.getenv("MYSQL_HOST")
        mysql_port = os.getenv("MYSQL_PORT")
        mysql_database = os.getenv("MYSQL_DATABASE")
        app.config["SQLALCHEMY_DATABASE_URI"] = (
            f"mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/{mysql_database}"
        )
        app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
        app.config["UPLOAD_FOLDER"] = os.getenv("UPLOAD_FOLDER", "uploads")
    else:
        app.config.update(test_config)

    # Configurar Flask-Limiter con backend en memoria
    limiter = Limiter(
        key_func=lambda: get_jwt_identity() if request.endpoint in ['save_palette', 'save_color', 'upload_image'] else get_remote_address(),
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )

    CORS(app, resources={r"/api/*": {"origins": ["https://cool-pics-up.vercel.app", "http://localhost:5173"]}})
    db.init_app(app)
    jwt.init_app(app)

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    with app.app_context():
        db.create_all()

    # Manejador global de errores
    @app.errorhandler(Exception)
    def handle_error(error):
        print(f"Global error: {str(error)}")
        return jsonify({"message": f"Error inesperado: {str(error)}"}), 500

    # Validar extensiones de archivo
    def allowed_file(filename):
        return "." in filename and filename.rsplit(".", 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

    # Validación básica de email
    def is_valid_email(email):
        return '@' in email and email.strip() != ''

    # Extraer colores predominantes de una imagen
    def extract_colors(image_path, num_colors=5):
        img = PILImage.open(image_path).convert("RGB")
        img = img.resize((100, 100))
        pixels = img.getdata()
        color_counts = {}
        for pixel in pixels:
            color_counts[pixel] = color_counts.get(pixel, 0) + 1
        sorted_colors = sorted(color_counts.items(), key=lambda x: x[1], reverse=True)[:num_colors]
        
        colors = []
        for (r, g, b), _ in sorted_colors:
            hex_color = f"#{r:02x}{g:02x}{b:02x}"
            h, l, s = colorsys.rgb_to_hls(r / 255.0, g / 255.0, b / 255.0)
            colors.append({
                "rgb": f"{r},{g},{b}",
                "hex": hex_color,
                "hsl": f"{int(h*360)},{int(s*100)}%,{int(l*100)}%"
            })
        return colors

    # Manejadores de errores para JWT
    @jwt.unauthorized_loader
    def unauthorized_callback(error):
        print(f"JWT Unauthorized error: {str(error)}")
        return jsonify({'message': 'Falta el token de autenticación'}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        print(f"JWT Invalid token error: {str(error)}")
        return jsonify({'message': 'Token inválido', 'details': str(error)}), 401

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        print(f"JWT Expired token error: exp={jwt_payload['exp']}, current_time={int(datetime.now(cst_tz).timestamp())}")
        return jsonify({'message': 'El token ha expirado'}), 401

    # Endpoint: Registro
    @app.route("/api/auth/register", methods=["POST"])
    def register():
        try:
            data = request.get_json()
            print("Registering user with:", data)

            first_name = bleach.clean(data.get("first_name", ""))
            last_name = bleach.clean(data.get("last_name", ""))
            username = bleach.clean(data.get("username", ""))
            email = bleach.clean(data.get("email", ""))
            password = data.get("password")
            confirm_password = data.get("confirmPassword")

            if not all([first_name, last_name, username, email, password]):
                print("Missing required fields")
                return jsonify({"message": "Faltan datos requeridos"}), 400

            if password != confirm_password:
                print("Passwords do not match")
                return jsonify({"message": "Las contraseñas no coinciden"}), 400

            if not is_valid_email(email):
                print(f"Invalid email format: {email}")
                return jsonify({"message": "El email debe contener '@'"}), 400

            if len(first_name) > 50 or len(last_name) > 50 or len(username) > 50:
                print("Field length exceeds limit")
                return jsonify({"message": "Los campos first_name, last_name o username no pueden exceder 50 caracteres"}), 422

            if User.query.filter_by(email=email).first():
                print(f"Email already registered: {email}")
                return jsonify({"message": "El email ya está registrado"}), 400
            if User.query.filter_by(username=username).first():
                print(f"Username already registered: {username}")
                return jsonify({"message": "El username ya está registrado"}), 400

            hashed_password = generate_password_hash(password)
            print("Generated hash:", hashed_password)

            new_user = User(
                first_name=first_name,
                last_name=last_name,
                username=username,
                email=email,
                password=hashed_password
            )
            db.session.add(new_user)
            db.session.commit()

            access_token = create_access_token(
                identity=str(new_user.id),
                expires_delta=timedelta(hours=24)
            )

            print(f"User registered: {email}")
            return jsonify({
                "message": "Usuario registrado exitosamente",
                "token": access_token,
                "user": {
                    "id": new_user.id,
                    "username": new_user.username,
                    "email": new_user.email,
                    "first_name": new_user.first_name,
                    "last_name": new_user.last_name
                }
            }), 201

        except IntegrityError as e:
            db.session.rollback()
            print(f"IntegrityError: {str(e)}")
            return jsonify({'message': 'Error de validación: Los datos no cumplen con las restricciones de la base de datos', 'details': str(e)}), 422
        except DataError as e:
            db.session.rollback()
            print(f"DataError: {str(e)}")
            return jsonify({'message': 'Error de datos: Los valores enviados exceden los límites permitidos', 'details': str(e)}), 422
        except Exception as e:
            db.session.rollback()
            print(f"Unexpected error: {str(e)}")
            return jsonify({"message": f"Error al registrar usuario: {str(e)}"}), 500

    # Endpoint: Login
    @app.route("/api/login", methods=["POST"])
    @limiter.limit("10 per minute")
    def login():
        data = request.get_json()
        email = bleach.clean(data.get("email", ""))
        password = data.get("password")
        print(f"Login attempt - Email: {email}")
        if not email or not password:
            return jsonify({"message": "Faltan email o contraseña"}), 400

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            return jsonify({"message": "Credenciales inválidas"}), 401

        access_token = create_access_token(
            identity=str(user.id),
            expires_delta=timedelta(hours=24)
        )
        print(f"Login successful for user: {email}, token expires in 24 hours")
        return jsonify({
            "token": access_token,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name
            },
            "message": "Inicio de sesión exitoso"
        }), 200

    # Endpoint: Subir imagen y generar paleta
    @app.route("/api/upload", methods=["POST"])
    @jwt_required()
    @limiter.limit("5 per minute")
    def upload_image():
        user_id = get_jwt_identity()
        print(f"User ID from token: {user_id}")

        # Verificar límite de paletas
        palette_count = Palette.query.filter_by(user_id=user_id).count()
        if palette_count >= 100:
            print(f"User {user_id} exceeded palette limit: {palette_count}")
            return jsonify({"message": "Límite de 100 paletas alcanzado"}), 429

        if "file" not in request.files:
            return jsonify({"message": "No se proporcionó archivo"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"message": "Nombre de archivo vacío"}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(f"{int(datetime.now(cst_tz).timestamp())}_{file.filename}")
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            colors = extract_colors(filepath, num_colors=7)
            
            new_palette = Palette(user_id=user_id, name=f"Palette_{int(datetime.now(cst_tz).timestamp())}", created_at=datetime.now(cst_tz))
            db.session.add(new_palette)
            db.session.flush()

            for i, color in enumerate(colors):
                new_color = PaletteColor(
                    palette_id=new_palette.id,
                    rgb=color["rgb"],
                    hex=color["hex"],
                    hsl=color["hsl"],
                    position=i
                )
                db.session.add(new_color)

            db.session.commit()
            print(f"Palette created from upload for user {user_id}: palette_id={new_palette.id}")
            return jsonify({"message": "Imagen subida y paleta generada", "palette_id": new_palette.id}), 200

        return jsonify({"message": "Archivo no permitido"}), 400

    # Endpoint: Listar paletas
    @app.route("/api/palettes", methods=["GET"])
    @jwt_required()
    def get_palettes():
        user_id = get_jwt_identity()
        print(f"User ID from token: {user_id}")
        
        palettes = Palette.query.filter_by(user_id=user_id).all()
        
        return jsonify({
            "palettes": [
                {
                    "id": p.id,
                    "name": p.name,
                    "created_at": p.created_at.astimezone(cst_tz).isoformat(),
                    "colors": [
                        {
                            "rgb": c.rgb,
                            "hex": c.hex,
                            "hsl": c.hsl,
                            "position": c.position
                        }
                        for c in sorted(p.colors, key=lambda x: x.position)
                    ]
                }
                for p in palettes
            ]
        }), 200

    # Endpoint: Eliminar paleta
    @app.route("/api/palettes/<int:palette_id>", methods=["DELETE"])
    @jwt_required()
    def delete_palette(palette_id):
        user_id = get_jwt_identity()
        palette = Palette.query.filter_by(id=palette_id, user_id=user_id).first()
        
        if not palette:
            return jsonify({"message": f"Paleta con ID {palette_id} no encontrada o no autorizada para el usuario {user_id}"}), 404
        
        try:
            db.session.delete(palette)
            db.session.commit()
            print(f"Paleta eliminada con éxito: ID {palette_id} para usuario {user_id}, colores asociados eliminados en cascada")
            return jsonify({"message": "Paleta eliminada exitosamente"}), 200
        except Exception as e:
            db.session.rollback()
            print(f"Error al eliminar paleta: {str(e)}")
            return jsonify({"message": f"Error al eliminar la paleta: {str(e)}"}), 500

    # Endpoint: Guardar paleta
    @app.route('/api/palettes', methods=['POST'])
    @jwt_required()
    @limiter.limit("5 per minute")
    def save_palette():
        print("Authorization header:", request.headers.get('Authorization'))
        print("Entering save_palette endpoint")
        try:
            user_id = get_jwt_identity()
            print(f"User ID from token: {user_id}")
            user = User.query.get(user_id)
            if not user:
                print(f"User not found for userId: {user_id}")
                return jsonify({'message': 'Usuario no encontrado'}), 404

            # Verificar límite de paletas
            palette_count = Palette.query.filter_by(user_id=user_id).count()
            if palette_count >= 100:
                print(f"User {user_id} exceeded palette limit: {palette_count}")
                return jsonify({"message": "Límite de 100 paletas alcanzado"}), 429

            data = request.get_json() or {}
            print(f"Received data: {data}")
            colors = data.get('colors', [])
            palette_name = bleach.clean(data.get('palette_name', 'Generated Palette'))

            if not palette_name.strip():
                print("Palette name empty after sanitization")
                return jsonify({'message': 'El nombre de la paleta no puede estar vacío después de sanitización'}), 400

            if not colors or not isinstance(colors, list):
                print("Invalid or missing colors array")
                return jsonify({'message': 'Faltan los colores o no es un array válido'}), 400

            if len(colors) > 10:
                print("Too many colors")
                return jsonify({'message': 'Máximo 10 colores permitidos'}), 400

            # Verificar colores duplicados
            color_set = set(tuple(c.get(k) for k in ['rgb', 'hex', 'hsl']) for c in colors)
            if len(color_set) < len(colors):
                print("Duplicate colors detected")
                return jsonify({'message': 'No se permiten colores duplicados en la paleta'}), 400

            new_palette = Palette(user_id=user.id, name=palette_name, created_at=datetime.now(cst_tz))
            db.session.add(new_palette)
            db.session.flush()

            for i, color in enumerate(colors):
                if not all(k in color for k in ['rgb', 'hex', 'hsl']):
                    print(f"Invalid color format at index {i}: {color}")
                    db.session.rollback()
                    return jsonify({'message': f'Formato inválido para el color en la posición {i}'}), 400

                new_color = PaletteColor(
                    palette_id=new_palette.id,
                    rgb=color['rgb'],
                    hex=color['hex'],
                    hsl=color['hsl'],
                    position=i
                )
                db.session.add(new_color)

            db.session.commit()
            print(f"Palette saved: {new_palette.id}, {palette_name} for user {user.id}")

            return jsonify({
                'message': 'Paleta guardada exitosamente',
                'palette_id': new_palette.id
            }), 201

        except IntegrityError as e:
            db.session.rollback()
            print(f"IntegrityError: {str(e)}")
            return jsonify({'message': 'Error de validación: Los datos no cumplen con las restricciones de la base de datos', 'details': str(e)}), 422
        except DataError as e:
            db.session.rollback()
            print(f"DataError: {str(e)}")
            return jsonify({'message': 'Error de datos: Los valores enviados exceden los límites permitidos', 'details': str(e)}), 422
        except Exception as e:
            db.session.rollback()
            print(f"Unexpected error: {str(e)}")
            return jsonify({'message': f'Error al guardar la paleta: {str(e)}'}), 500

    # Endpoint: Guardar color
    @app.route('/api/colors', methods=['POST'])
    @jwt_required()
    @limiter.limit("5 per minute")
    def save_color():
        print("Authorization header:", request.headers.get('Authorization'))
        print("Entering save_color endpoint")
        try:
            user_id = get_jwt_identity()
            print(f"User ID from token: {user_id}")
            user = User.query.get(user_id)
            if not user:
                print(f"User not found for userId: {user_id}")
                return jsonify({'message': 'Usuario no encontrado'}), 404

            # Verificar límite de colores
            color_count = Color.query.filter_by(user_id=user_id).count()
            if color_count >= 500:
                print(f"User {user_id} exceeded color limit: {color_count}")
                return jsonify({"message": "Límite de 500 colores alcanzado"}), 429

            data = request.get_json() or {}
            print(f"Received data: {data}")
            rgb = data.get('rgb')
            hex = data.get('hex')
            hsl = data.get('hsl')
            name = bleach.clean(data.get('name', ''))

            if not all([rgb, hex, hsl, name]):
                missing = [key for key, value in {'rgb': rgb, 'hex': hex, 'hsl': hsl, 'name': name}.items() if not value]
                print(f"Missing required fields: {missing}")
                return jsonify({'message': f'Faltan datos requeridos: {", ".join(missing)}'}), 400

            if not name.strip():
                print("Color name empty after sanitization")
                return jsonify({'message': 'El nombre del color no puede estar vacío después de sanitización'}), 400

            rgb_values = rgb.split(',')
            if len(rgb_values) != 3 or not all(v.isdigit() for v in rgb_values):
                print("Invalid RGB format")
                return jsonify({'message': 'Formato de RGB inválido, esperado: "r,g,b"'}), 422
            rgb_nums = [int(v) for v in rgb_values]
            if not all(0 <= v <= 255 for v in rgb_nums):
                print("Invalid RGB values")
                return jsonify({'message': 'Valores de RGB fuera de rango (0-255)'}), 422

            if not hex.startswith('#') or len(hex) != 7:
                print("Invalid HEX format")
                return jsonify({'message': 'Formato de HEX inválido'}), 422

            hsl_values = hsl.split(',')
            if len(hsl_values) != 3 or not all(v.replace('%', '').isdigit() for v in hsl_values):
                print("Invalid HSL format")
                return jsonify({'message': 'Formato de HSL inválido, esperado: "h,s,l"'}), 422
            hsl_nums = [float(v.replace('%', '')) for v in hsl_values]
            if not (0 <= hsl_nums[0] <= 360 and 0 <= hsl_nums[1] <= 100 and 0 <= hsl_nums[2] <= 100):
                print("Invalid HSL values")
                return jsonify({'message': 'Valores de HSL fuera de rango (h: 0-360, s/l: 0-100)'}), 422

            if len(name) > 50:
                print("Name exceeds 50 characters")
                return jsonify({'message': 'El nombre no puede exceder 50 caracteres'}), 422

            new_color = Color(
                user_id=user.id,
                rgb=rgb,
                hex=hex,
                hsl=hsl,
                name=name,
                created_at=datetime.now(cst_tz)
            )
            db.session.add(new_color)
            print(f"Before flush: new_color = {new_color.__dict__}")
            db.session.flush()
            db.session.commit()
            print(f"Color saved: {new_color.id}, {name} for user {user.id}")

            return jsonify({
                'message': 'Color guardado exitosamente',
                'color': {
                    'id': new_color.id,
                    'user_id': new_color.user_id,
                    'rgb': new_color.rgb,
                    'hex': new_color.hex,
                    'hsl': new_color.hsl,
                    'name': new_color.name,
                    'created_at': new_color.created_at.astimezone(cst_tz).isoformat()
                }
            }), 201

        except IntegrityError as e:
            db.session.rollback()
            print(f"IntegrityError: {str(e)}")
            return jsonify({'message': 'Error de validación: Los datos no cumplen con las restricciones de la base de datos', 'details': str(e)}), 422
        except DataError as e:
            db.session.rollback()
            print(f"DataError: {str(e)}")
            return jsonify({'message': 'Error de datos: Los valores enviados exceden los límites permitidos', 'details': str(e)}), 422
        except Exception as e:
            db.session.rollback()
            print(f"Unexpected error: {str(e)}")
            return jsonify({'message': f'Error al guardar el color: {str(e)}'}), 500

    # Endpoint: Eliminar color
    @app.route('/api/colors/<int:color_id>', methods=['DELETE'])
    @jwt_required()
    def delete_color(color_id):
        print(f"Entering delete_color endpoint for color_id: {color_id}")
        try:
            user_id = get_jwt_identity()
            print(f"User ID from token: {user_id}")
            color = Color.query.filter_by(id=color_id, user_id=user_id).first()

            if not color:
                print(f"Color not found or not owned by user: {color_id}")
                return jsonify({'message': 'Color no encontrado o no tienes permiso para eliminarlo'}), 404

            db.session.delete(color)
            db.session.commit()
            print(f"Color deleted: {color_id} for user {user_id}")

            return jsonify({'message': 'Color eliminado exitosamente'}), 200

        except Exception as e:
            db.session.rollback()
            print(f"Unexpected error: {str(e)}")
            return jsonify({'message': f'Error al eliminar el color: {str(e)}'}), 500

    # Endpoint: Listar colores con paginación
    @app.route("/api/colors", methods=["GET"])
    @jwt_required()
    def get_colors():
        user_id = get_jwt_identity()
        print(f"User ID from token: {user_id}")
        
        page = request.args.get('page', default=1, type=int)
        limit = request.args.get('limit', default=20, type=int)

        if page < 1:
            print(f"Invalid page number: {page}")
            return jsonify({"message": "El número de página debe ser mayor o igual a 1"}), 400

        start = (page - 1) * limit
        
        colors = Color.query.filter_by(user_id=user_id).offset(start).limit(limit).all()
        total_colors = Color.query.filter_by(user_id=user_id).count()
        has_more = total_colors > start + len(colors)
        
        return jsonify({
            "colors": [
                {
                    "id": c.id,
                    "rgb": c.rgb,
                    "hex": c.hex,
                    "hsl": c.hsl,
                    "name": c.name,
                    "created_at": c.created_at.astimezone(cst_tz).isoformat()
                }
                for c in colors
            ],
            "has_more": has_more
        }), 200

    # Endpoint: Convertir color
    @app.route("/api/convert", methods=["POST"])
    @jwt_required()
    def convert_color():
        data = request.get_json()
        color_input = data.get("color")
        input_format = data.get("input_format")
        output_format = data.get("output_format")

        def rgb_to_hex(r, g, b):
            return f"#{r:02x}{g:02x}{b:02x}"

        def rgb_to_hsl(r, g, b):
            r, g, b = r / 255.0, g / 255.0, b / 255.0
            h, l, s = colorsys.rgb_to_hls(r, g, b)
            return f"{int(h*360)},{int(s*100)}%,{int(l*100)}%"

        def hex_to_rgb(hex_color):
            hex_color = hex_color.lstrip("#")
            return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

        def hsl_to_rgb(hsl):
            h, s, l = map(float, hsl.replace("%", "").split(","))
            h /= 360.0
            s /= 100.0
            l /= 100.0
            r, g, b = colorsys.hls_to_rgb(h, l, s)
            return int(r * 255), int(g * 255), int(b * 255)

        try:
            if input_format == "rgb":
                r, g, b = map(int, color_input.split(","))
            elif input_format == "hex":
                r, g, b = hex_to_rgb(color_input)
            elif input_format == "hsl":
                r, g, b = hsl_to_rgb(color_input)
            else:
                return jsonify({"message": "Formato de entrada no soportado"}), 400

            if output_format == "rgb":
                result = f"{r},{g},{b}"
            elif output_format == "hex":
                result = rgb_to_hex(r, g, b)
            elif output_format == "hsl":
                result = rgb_to_hsl(r, g, b)
            else:
                return jsonify({"message": "Formato de salida no soportado"}), 400

            return jsonify({"converted_color": result}), 200
        except ValueError as e:
            print(f"Error en conversión de color: {str(e)}")
            return jsonify({"message": f"Error en la conversión del color: {str(e)}"}), 400

    # Endpoint: Actualizar perfil
    @app.route('/api/auth/profile', methods=['PUT'])
    @jwt_required()
    def update_profile():
        try:
            user_id = get_jwt_identity()
            print(f"User ID from token: {user_id}")
            user = User.query.get(user_id)
            if not user:
                print("User not found")
                return jsonify({'message': 'Usuario no encontrado'}), 404

            data = request.get_json() or {}
            print(f"Received data: {data}")
            first_name = bleach.clean(data.get('first_name', user.first_name))
            last_name = bleach.clean(data.get('last_name', user.last_name))
            username = bleach.clean(data.get('username', user.username))
            email = bleach.clean(data.get('email', user.email))
            password = data.get('password')
            confirm_password = data.get('confirmPassword')

            if 'first_name' in data and not first_name:
                print("Validation failed: first_name is empty")
                return jsonify({'message': 'El nombre es requerido'}), 400
            if 'last_name' in data and not last_name:
                print("Validation failed: last_name is empty")
                return jsonify({'message': 'El apellido es requerido'}), 400
            if 'username' in data and not username:
                print("Validation failed: username is empty")
                return jsonify({'message': 'El nombre de usuario es requerido'}), 400
            if 'email' in data and not email:
                print("Validation failed: email is empty")
                return jsonify({'message': 'El correo electrónico es requerido'}), 400

            if 'email' in data and not is_valid_email(email):
                print(f"Invalid email format: {email}")
                return jsonify({"message": "El email debe contener '@'"}), 400

            if 'username' in data and username != user.username:
                print(f"Checking username uniqueness: {username}")
                existing_user = User.query.filter_by(username=username).first()
                if existing_user:
                    print("Username already in use")
                    return jsonify({'message': 'El nombre de usuario ya está en uso'}), 400

            if 'email' in data and email != user.email:
                print(f"Checking email uniqueness: {email}")
                existing_email = User.query.filter_by(email=email).first()
                if existing_email:
                    print("Email already in use")
                    return jsonify({'message': 'El correo electrónico ya está en uso'}), 400

            if 'first_name' in data:
                user.first_name = first_name
            if 'last_name' in data:
                user.last_name = last_name
            if 'username' in data:
                user.username = username
            if 'email' in data:
                user.email = email

            if password is not None:
                print("Updating password")
                if not confirm_password or password != confirm_password:
                    print("Passwords do not match")
                    return jsonify({'message': 'Las contraseñas no coinciden'}), 400
                user.password = generate_password_hash(password)

            print("Attempting to flush and commit changes")
            db.session.flush()
            db.session.commit()

            print("Changes committed successfully")
            return jsonify({
                'message': 'Perfil actualizado exitosamente',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name
                }
            }), 200

        except IntegrityError as e:
            db.session.rollback()
            print(f"IntegrityError: {str(e)}")
            return jsonify({'message': 'Error de validación: Los datos no cumplen con las restricciones de la base de datos', 'details': str(e)}), 422
        except DataError as e:
            db.session.rollback()
            print(f"DataError: {str(e)}")
            return jsonify({'message': 'Error de datos: Los valores enviados exceden los límites permitidos', 'details': str(e)}), 422
        except Exception as e:
            db.session.rollback()
            print(f"Unexpected error: {str(e)}")
            return jsonify({'message': f'Error al actualizar el perfil: {str(e)}'}), 500
    @app.route('/', methods=['GET', 'HEAD'])
    def health_check():
        return jsonify({"message": "Backend is running"}), 200

    return app
app = create_app()
if __name__ == "__main__":
    
    port = int(os.getenv("FLASK_PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
