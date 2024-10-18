# pylint: disable=unused-import
import argparse
import binascii
import datetime
import io
from flask import Flask, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS  
from werkzeug.security import check_password_hash, generate_password_hash
from flask_migrate import Migrate

#python3 app.py --host 0.0.0.0 --port 8080

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import BadRequest

from config import (
    CTR_PARAM,
    ENC_FILE_DATA_PARAM,
    ENC_PICC_DATA_PARAM,
    REQUIRE_LRP,
    SDMMAC_PARAM,
    MASTER_KEY,
    UID_PARAM,
    DERIVE_MODE,
)

if DERIVE_MODE == "legacy":
    from libsdm.legacy_derive import derive_tag_key, derive_undiversified_key
elif DERIVE_MODE == "standard":
    from libsdm.derive import derive_tag_key, derive_undiversified_key
else:
    raise RuntimeError("Invalid DERIVE_MODE.")

from libsdm.sdm import (
    EncMode,
    InvalidMessage,
    ParamMode,
    decrypt_sun_message,
    validate_plain_sun,
)

from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import IntegrityError
import secrets
from flask import abort
import jwt
from datetime import datetime, timedelta, timezone
from flask import redirect, url_for
from sqlalchemy.orm import relationship
from sqlalchemy import Table, Column, Integer, String, ForeignKey, DateTime, Text, Enum
import enum

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)  # Enable CORS for all /api routes
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

# Add a secret key for JWT encoding/decoding
JWT_SECRET_KEY = 'Xt7q9P3mK2fL8wR4bN6vJ1zC5hA0yE3u'  # Randomly generated secret key

class RewardType(enum.Enum):
    IMAGE = 'image'
    VIDEO = 'video'
    FILE = 'file'

product_rewards = Table('product_rewards', db.Model.metadata,
    Column('product_id', Integer, ForeignKey('products.id')),
    Column('reward_id', Integer, ForeignKey('rewards.id'))
)

class Tags(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(32), unique=True, nullable=False)
    file_data = db.Column(db.String(200))
    read_ctr = db.Column(db.Integer, nullable=False, default=1)
    tt_status = db.Column(db.String(20))
    enc_mode = db.Column(db.String(20))
    picc_data_tag = db.Column(db.String(32))
    file_data_utf8 = db.Column(db.Text)
    tt_color = db.Column(db.String(10))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    claimed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'))
    product = db.relationship('Products', back_populates='tags')
    claim_password = db.Column(db.String(128), nullable=True)

    # Add a relationship to the User model
    claimed_by_user = relationship('User', back_populates='claimed_tags')

class Collection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    collection_name = db.Column(db.String(100), nullable=False)
    collection_image = db.Column(db.String(200))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    location = db.Column(db.String(200))

    user = db.relationship('User', backref=db.backref('collections', lazy=True))

class ContentBlock(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    type = db.Column(db.String(10))  # 'text' or 'media'
    content = db.Column(db.Text)
    order = db.Column(db.Integer, nullable=False)

class Products(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100), nullable=False)  
    product_image = db.Column(db.String(200))  
    collection_id = db.Column(db.Integer, db.ForeignKey('collection.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) 
    content_blocks = db.relationship('ContentBlock', backref='product', lazy=True, order_by='ContentBlock.order')

    collection = db.relationship('Collection', backref=db.backref('products', lazy=True))
    tags = db.relationship('Tags', back_populates='product')
    rewards = db.relationship('Rewards', secondary=product_rewards, back_populates='products')
    creator = db.relationship('User', backref=db.backref('created_products', lazy=True)) 

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50))
    profile_image = db.Column(db.String(200))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Add this line
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    claimed_tags = relationship('Tags', back_populates='claimed_by_user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        result = check_password_hash(self.password_hash, password)
        return result

class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_image = db.Column(db.String(200), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    post_caption = db.Column(db.Text)
    collection_id = db.Column(db.Integer, db.ForeignKey('collection.id'), nullable=False)
    pinned = db.Column(db.Boolean, default=False)  

    user = db.relationship('User', backref=db.backref('posts', lazy=True))
    collection = db.relationship('Collection', backref=db.backref('posts', lazy=True))

class Rewards(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    type = db.Column(db.Enum(RewardType), nullable=False)
    content_url = db.Column(db.String(200), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    products = db.relationship('Products', secondary=product_rewards, back_populates='rewards')

class Claims(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tag_id = db.Column(db.Integer, db.ForeignKey('tags.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    claim_datetime = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    tag = db.relationship('Tags', backref=db.backref('claims', lazy=True))
    user = db.relationship('User', backref=db.backref('claims', lazy=True))

@app.errorhandler(400)
def handler_bad_request(err):
    return render_template('error.html', code=400, msg=str(err)), 400

@app.errorhandler(403)
def handler_forbidden(err):
    return render_template('error.html', code=403, msg=str(err)), 403

@app.errorhandler(404)
def handler_not_found(err):
    return render_template('error.html', code=404, msg=str(err)), 404

@app.context_processor
def inject_demo_mode():
    demo_mode = MASTER_KEY == (b"\x00" * 16)
    return {"demo_mode": demo_mode}

# pylint:  disable=too-many-branches
def parse_parameters():
    arg_e = request.args.get('e')
    if arg_e:
        param_mode = ParamMode.BULK

        try:
            e_b = binascii.unhexlify(arg_e)
        except binascii.Error:
            raise BadRequest("Failed to decode parameters.") from None

        e_buf = io.BytesIO(e_b)

        if (len(e_b) - 8) % 16 == 0:
            # using AES (16 byte PICCEncData)
            file_len = len(e_b) - 16 - 8
            enc_picc_data_b = e_buf.read(16)

            if file_len > 0:
                enc_file_data_b = e_buf.read(file_len)
            else:
                enc_file_data_b = None

            sdmmac_b = e_buf.read(8)
        elif (len(e_b) - 8) % 16 == 8:
            # using LRP (24 byte PICCEncData)
            file_len = len(e_b) - 24 - 8
            enc_picc_data_b = e_buf.read(24)

            if file_len > 0:
                enc_file_data_b = e_buf.read(file_len)
            else:
                enc_file_data_b = None

            sdmmac_b = e_buf.read(8)
        else:
            raise BadRequest("Incorrect length of the dynamic parameter.")
    else:
        param_mode = ParamMode.SEPARATED
        enc_picc_data = request.args.get(ENC_PICC_DATA_PARAM)
        enc_file_data = request.args.get(ENC_FILE_DATA_PARAM)
        sdmmac = request.args.get(SDMMAC_PARAM)

        if not enc_picc_data:
            raise BadRequest(f"Parameter {ENC_PICC_DATA_PARAM} is required")

        if not sdmmac:
            raise BadRequest(f"Parameter {SDMMAC_PARAM} is required")

        try:
            enc_file_data_b = None
            enc_picc_data_b = binascii.unhexlify(enc_picc_data)
            sdmmac_b = binascii.unhexlify(sdmmac)

            if enc_file_data:
                enc_file_data_b = binascii.unhexlify(enc_file_data)
        except binascii.Error:
            raise BadRequest("Failed to decode parameters.") from None

    return param_mode, enc_picc_data_b, enc_file_data_b, sdmmac_b

@app.route('/api/tagtt')
def sdm_api_info_tt():
    try:
        return _internal_sdm(with_tt=True)
    except BadRequest as err:
        return jsonify({"error": str(err)})

# pylint:  disable=too-many-branches, too-many-statements, too-many-locals
def _internal_sdm(with_tt=False):
    """
    SUN decrypting/validating endpoint.
    """
    param_mode, enc_picc_data_b, enc_file_data_b, sdmmac_b = parse_parameters()

    try:
        res = decrypt_sun_message(param_mode=param_mode,
                                  sdm_meta_read_key=derive_undiversified_key(MASTER_KEY, 1),
                                  sdm_file_read_key=lambda uid: derive_tag_key(MASTER_KEY, uid, 2),
                                  picc_enc_data=enc_picc_data_b,
                                  sdmmac=sdmmac_b,
                                  enc_file_data=enc_file_data_b)
    except InvalidMessage:
        raise BadRequest("Invalid message (most probably wrong signature).") from InvalidMessage

    if REQUIRE_LRP and res['encryption_mode'] != EncMode.LRP:
        raise BadRequest("Invalid encryption mode, expected LRP.")

    picc_data_tag = res['picc_data_tag']
    uid = res['uid']
    read_ctr_num = res['read_ctr']
    file_data = res['file_data']
    encryption_mode = res['encryption_mode'].name

    file_data_utf8 = ""
    tt_status_api = ""
    tt_status = ""
    tt_color = ""

    print("read_ctr_num: ", read_ctr_num)


    if res['file_data']:
        if param_mode == ParamMode.BULK:
            file_data_len = file_data[2]
            file_data_unpacked = file_data[3:3 + file_data_len]
        else:
            file_data_unpacked = file_data

        file_data_utf8_raw = file_data_unpacked.decode('utf-8', 'ignore')
        file_data_utf8_clean = file_data_utf8_raw.rstrip('\x00')[2:]

        if with_tt:
            tt_perm_status = file_data[0:1].decode('ascii', 'replace')
            tt_cur_status = file_data[1:2].decode('ascii', 'replace')

            if tt_perm_status == 'C' and tt_cur_status == 'C':
                tt_status_api = 'secure'
                tt_status = 'OK (not tampered)'
                tt_color = 'green'
            elif tt_perm_status == 'O' and tt_cur_status == 'C':
                tt_status_api = 'tampered_closed'
                tt_status = 'Tampered! (loop closed)'
                tt_color = 'red'
            elif tt_perm_status == 'O' and tt_cur_status == 'O':
                tt_status_api = 'tampered_open'
                tt_status = 'Tampered! (loop open)'
                tt_color = 'red'
            elif tt_perm_status == 'I' and tt_cur_status == 'I':
                tt_status_api = 'not_initialized'
                tt_status = 'Not initialized'
                tt_color = 'orange'
            elif tt_perm_status == 'N' and tt_cur_status == 'T':
                tt_status_api = 'not_supported'
                tt_status = 'Not supported by the tag'
                tt_color = 'orange'
            else:
                tt_status_api = 'unknown'
                tt_status = 'Unknown'
                tt_color = 'orange'



    existing_data = Tags.query.filter_by(uid=uid.hex().upper()).first()

    is_authentic = False
    if existing_data:
        is_authentic = read_ctr_num > existing_data.read_ctr 

    print("uid: ", uid.hex().upper())
    
    if existing_data:
        # Update existing record
        existing_data.file_data = file_data.hex() if file_data else None
        existing_data.read_ctr = read_ctr_num
        existing_data.tt_status = tt_status_api
        existing_data.enc_mode = encryption_mode
        existing_data.picc_data_tag = picc_data_tag.hex() if picc_data_tag else None
        existing_data.file_data_utf8 = file_data_utf8_clean if 'file_data_utf8_clean' in locals() else None
        existing_data.tt_color = tt_color
        existing_data.timestamp = datetime.now(timezone.utc)

        db.session.commit()

        if is_authentic:
            # Generate a JWT instead of a one-time token
            expiration_time = datetime.now(timezone.utc) + timedelta(minutes=60)  # Token expires in 5 minutes
            token = jwt.encode({
                'uid': uid.hex().upper(),
                'exp': expiration_time
            }, JWT_SECRET_KEY, algorithm='HS256')

            return jsonify({
                "is_authentic": True,
                "uid": uid.hex().upper(),
                "token": token
            })
        else:
            return jsonify({
                "is_authentic": False,
                "uid": uid.hex().upper(),
            })
    else:
        return jsonify({
            "is_authentic": False,
            "uid": uid.hex().upper(),
        })

@app.route('/api/product/<uid>', methods=['GET', 'OPTIONS'])
def get_product_info(uid):
    if request.method == 'OPTIONS':
        response = app.make_default_options_response()
    else:
        token = request.args.get('token')
        auth_token = request.args.get('auth_token')

        fetch_as_creator_or_owner = auth_token and not token 

        if not token and not auth_token:
            return jsonify({"error": "Token or auth_token is required"}), 400
        try:
            # Verify the JWT
            if fetch_as_creator_or_owner:
                try:
                    # Verify the JWT
                    payload = jwt.decode(auth_token, JWT_SECRET_KEY, algorithms=['HS256'])
                    user_id = payload['user_id']
                    print("user_id: ", user_id)
                except jwt.ExpiredSignatureError:
                    return jsonify({"error": "Token has expired. Please log in again."}), 401
                except jwt.InvalidTokenError:
                    return jsonify({"error": "Invalid token"}), 401
            else:
                payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
                if payload['uid'] != uid:
                    raise jwt.InvalidTokenError
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired. Tap the NFC tag again."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        # Fetch the tag information
        tag = Tags.query.filter_by(uid=uid).first()
        if not tag:
            return jsonify({"error": "Tag not found"}), 404
        
        if fetch_as_creator_or_owner:
            print("tag.product.creator.id: ", tag.product.creator.id)
            print("tag.claimed_by: ", tag.claimed_by)
            print("user_id: ", user_id)
            if tag.product.creator.id != user_id and tag.claimed_by != user_id:
                return jsonify({"error": "You do not have access to view this tag"}), 403

        # Get the associated product
        product = tag.product
        if not product:
            return jsonify({"error": "Product not found"}), 404

        collection = product.collection
        
        # Handle the case where last_name might be None or an empty string
        creator_name = collection.user.first_name
        if collection.user.last_name:
            creator_name += f" {collection.user.last_name}"

        # Fetch and sort content blocks
        content_blocks = sorted(product.content_blocks, key=lambda x: x.order)
        content_blocks_data = [
            {
                "id": block.id,
                "type": block.type,
                "content": block.content,
                "order": block.order
            } for block in content_blocks
        ]

        response = jsonify({
            "product_id": product.id,
            "product_name": product.product_name,
            "product_image": product.product_image,
            "collection_id": collection.id,
            "collection_name": collection.collection_name,
            "collection_image": collection.collection_image,
            "location": collection.location,
            "date": collection.date.isoformat() if isinstance(collection.date, datetime) else collection.date,
            "created_by_name": creator_name,
            "creator_image": collection.user.profile_image,
            "claimed": tag.claimed_by,
            "creator_id": product.creator.id,
            "content_blocks": content_blocks_data  
        })

    # Add CORS headers to the response
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route('/api/collection/<uid>/<int:collection_id>/posts', methods=['GET'])
def get_collection_posts(uid,collection_id):
    token = request.args.get('token')
    auth_token = request.args.get('auth_token')

    fetch_as_creator_or_owner = auth_token and not token 

    if not uid or (not token and not auth_token):
        return jsonify({"error": "UID and token or auth_token are required"}), 400

    try:
        # Verify the JWT
        if fetch_as_creator_or_owner:
            try:
                # Verify the JWT
                payload = jwt.decode(auth_token, JWT_SECRET_KEY, algorithms=['HS256'])
                user_id = payload['user_id']
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token has expired. Please log in again."}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Invalid token"}), 401
        else:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
            if payload['uid'] != uid:
                raise jwt.InvalidTokenError
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired. Tap the NFC tag again."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    # Check if the collection exists
    collection = Collection.query.get(collection_id)
    if not collection:
        return jsonify({"error": "Collection not found"}), 404
    
    if fetch_as_creator_or_owner:
        user_tags = Tags.query.filter_by(claimed_by=user_id).all()
        user_product_ids = [tag.product_id for tag in user_tags if tag.product_id is not None]
        collection_products = Products.query.filter_by(collection_id=collection_id).all()
        collection_product_ids = [product.id for product in collection_products]
            
        user_owns_collection = set(user_product_ids) & set(collection_product_ids)

        if  user_owns_collection:
            pass
        elif not collection or collection.created_by != user_id: 
            return jsonify({"error": "You cannot view this collection"}), 404
        else:
            return jsonify({"error": "You don't own any tags linked to this collection"}), 403

    # Query all posts for this collection, sorted by pinned status (pinned first) and then by date descending
    posts = Posts.query.filter_by(collection_id=collection_id).order_by(Posts.pinned.desc(), Posts.date.desc()).all()
    # Prepare the response data
    posts_data = []
    for post in posts:
        user_name = post.user.first_name
        if post.user.last_name:
            user_name += f" {post.user.last_name}"
        posts_data.append({
            "id": post.id,
            "user_name": user_name,
            "user_id": post.user.id,
            "user_image": post.user.profile_image,
            "post_image": post.post_image,
            "date": post.date.isoformat(),
            "post_caption": post.post_caption,
            "pinned": post.pinned 
        })

    creator_name = collection.user.first_name
    if collection.user.last_name:
        creator_name += f" {collection.user.last_name}"

    response = jsonify({
        "collection_id": collection_id,
        "collection_name": collection.collection_name,
        "collection_image": collection.collection_image,
        "location": collection.location,
        "date": collection.date.isoformat(),
        "created_by_name": creator_name,
        "created_by_id": collection.user.id,
        "creator_image": collection.user.profile_image,
        "posts": posts_data,
    })

    # Add CORS headers to the response
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        expiration_time = datetime.now(timezone.utc) + timedelta(days=1)  # Token expires in 1 day
        token = jwt.encode({
            'user_id': user.id,
            'exp': expiration_time
        }, JWT_SECRET_KEY, algorithm='HS256')

        return jsonify({
            "token": token,
            "user_id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "profile_image": user.profile_image
        }), 200
    else:
        return jsonify({"error": "Invalid email or password"}), 401

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    password = data.get('password')
    profile_image = data.get('profile_image')  # This could be a URL to an image

    if not first_name or not email or not password:
        return jsonify({"error": "First name, email, and password are required"}), 400

    # Check if user already exists
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "Email already registered"}), 409

    # Create new user
    new_user = User(
        first_name=first_name,
        last_name=last_name,
        email=email,
        profile_image=profile_image
    )
    new_user.set_password(password)

    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "An error occurred while registering the user"}), 500

    # Generate token for the new user
    expiration_time = datetime.now(timezone.utc) + timedelta(days=1)  # Token expires in 1 day
    token = jwt.encode({
        'user_id': new_user.id,
        'exp': expiration_time
    }, JWT_SECRET_KEY, algorithm='HS256')

    return jsonify({
        "message": "User registered successfully",
        "token": token,
        "user_id": new_user.id,
        "first_name": new_user.first_name,
        "last_name": new_user.last_name,
        "email": new_user.email,
        "profile_image": new_user.profile_image
    }), 201

@app.route('/api/claim-tag', methods=['POST'])
def claim_tag():
    data = request.get_json()
    uid = data.get('uid')
    token = data.get('token')
    submitted_password = data.get('submitted_password')

    if not uid or not token:
        return jsonify({"error": "UID and token are required"}), 400

    try:
        # Verify the JWT
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired. Please log in again."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401
    
    # Find the tag
    tag = Tags.query.filter_by(uid=uid).first()
    if not tag:
        return jsonify({"error": "Tag not found"}), 404

    # Check if the tag is already claimed
    if tag.claimed_by is not None:
        return jsonify({"error": "This tag has already been claimed"}), 400
    
    print("tag.claim_password: ", tag.claim_password)
    print("submitted_password: ", submitted_password)
    print("tag.claim_password == submitted_password: ", tag.claim_password == submitted_password)

    # Check if the submitted password is correct
    if not tag.claim_password == submitted_password:
        return jsonify({"error": "Incorrect password"}), 401

    # Claim the tag
    tag.claimed_by = user_id
    
    # Generate a new random password for the tag
    new_password = secrets.token_hex(16)  
    tag.claim_password = new_password

    # Create a new claim record
    new_claim = Claims(tag_id=tag.id, user_id=user_id)

    try:
        db.session.add(new_claim)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"An error occurred while claiming the tag: {str(e)}"}), 500

    return jsonify({"message": "Tag claimed successfully"}), 200

@app.route('/api/create-post', methods=['POST'])
def create_post():
    data = request.get_json()
    token = data.get('token')
    collection_id = data.get('collection_id')
    post_image = data.get('post_image')
    post_caption = data.get('post_caption')

    if not token or not collection_id or not post_image:
        return jsonify({"error": "Token, collection ID, and post image are required"}), 400

    try:
        # Verify the JWT
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired. Please log in again."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    # Check if the collection exists
    collection = Collection.query.get(collection_id)
    if not collection:
        return jsonify({"error": "Collection not found"}), 404

    # Create new post
    new_post = Posts(
        user_id=user_id,
        post_image=post_image,
        post_caption=post_caption,
        collection_id=collection_id,
        date=datetime.now(timezone.utc)
    )

    try:
        db.session.add(new_post)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"An error occurred while creating the post: {str(e)}"}), 500

    return jsonify({
        "message": "Post created successfully",
        "post_id": new_post.id,
        "user_id": new_post.user_id,
        "post_image": new_post.post_image,
        "post_caption": new_post.post_caption,
        "collection_id": new_post.collection_id,
        "date": new_post.date.isoformat()
    }), 201

@app.route('/api/product/<int:product_id>/rewards', methods=['GET'])
def get_product_rewards(product_id):
    # Get the token from the request headers
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Authorization token is required"}), 401

    try:
        # Verify the JWT
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired. Please log in again."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    # Find the product
    product = Products.query.get(product_id)
    if not product:
        return jsonify({"error": "Product not found"}), 404

    # Check if the user has claimed a tag linked to this product or created the product
    claimed_tag = Tags.query.filter_by(product_id=product_id, claimed_by=user_id).first()
    is_product_creator = product.created_by == user_id

    if not claimed_tag and not is_product_creator:
        return jsonify({"error": "You don't have access to this product's rewards"}), 403
    
    # Get all rewards for the product
    rewards = product.rewards

    # Prepare the response data
    rewards_data = []
    for reward in rewards:
        rewards_data.append({
            "id": reward.id,
            "name": reward.name,
            "description": reward.description,
            "type": reward.type.value,
            "content_url": reward.content_url,
            "date_created": reward.date_created.isoformat()
        })

    return jsonify({
        "product_id": product_id,
        "product_name": product.product_name,
        "rewards": rewards_data
    }), 200

@app.route('/api/create-collection', methods=['POST'])
def create_collection():
    data = request.get_json()
    token = data.get('token')
    collection_name = data.get('collection_name')
    collection_image = data.get('collection_image')
    location = data.get('location')
    date = data.get('date')

    if not token or not collection_name:
        return jsonify({"error": "Token and collection name are required"}), 400

    try:
        # Verify the JWT
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired. Please log in again."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    # Create new collection
    new_collection = Collection(
        collection_name=collection_name,
        collection_image=collection_image,
        created_by=user_id,
        date=date,
        location=location
    )

    try:
        db.session.add(new_collection)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"An error occurred while creating the collection: {str(e)}"}), 500

    return jsonify({
        "message": "Collection created successfully",
        "collection_id": new_collection.id,
        "collection_name": new_collection.collection_name,
        "collection_image": new_collection.collection_image,
        "created_by": new_collection.created_by,
        "date": new_collection.date.isoformat(),
        "location": new_collection.location
    }), 201

@app.route('/api/create-product', methods=['POST'])
def create_product():
    data = request.get_json()
    token = data.get('token')
    product_name = data.get('product_name')
    product_image = data.get('product_image')
    collection_id = data.get('collection_id')
    tag_uid = data.get('tag_uid')  
    content_blocks = data.get('content_blocks', [])

    if not token or not product_name or not collection_id or not tag_uid:
        return jsonify({"error": "Token, product name, collection ID, and tag UID are required"}), 400

    try:
        # Verify the JWT
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired. Please log in again."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    # Check if the collection exists and belongs to the user
    collection = Collection.query.filter_by(id=collection_id, created_by=user_id).first()
    if not collection:
        return jsonify({"error": "Collection not found or you don't have permission to add products to it"}), 404

    # Check if the tag exists and is not already linked to a product
    tag = Tags.query.filter_by(uid=tag_uid).first()
    if not tag:
        return jsonify({"error": "Tag not found"}), 404
    if tag.product_id is not None:
        return jsonify({"error": "This tag is already linked to a product"}), 400

    # Create new product
    new_product = Products(
        product_name=product_name,
        product_image=product_image,
        collection_id=collection_id,
        created_by=user_id
    )

    try:
        db.session.add(new_product)
        db.session.flush()  # This will assign an ID to new_product without committing the transaction

        # Link the tag to the new product
        tag.product_id = new_product.id

        # Add content blocks
        for index, block in enumerate(content_blocks):
            new_block = ContentBlock(
                product_id=new_product.id,
                type=block['type'],
                content=block['content'],
                order=index
            )
            db.session.add(new_block)

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"An error occurred while creating the product: {str(e)}"}), 500

    return jsonify({
        "message": "Product created successfully and linked to the tag",
        "product_id": new_product.id,
        "tag_uid": tag_uid
    }), 201



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    parser = argparse.ArgumentParser(description='OTA NFC Server')
    parser.add_argument('--host', type=str, nargs='?', help='address to listen on')
    parser.add_argument('--port', type=int, nargs='?', help='port to listen on')

    args = parser.parse_args()

    app.run(host=args.host, port=args.port)