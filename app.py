from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import os

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "super-secret-key")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- MANY-TO-MANY TABLE ---
item_categories = db.Table(
    'item_categories',
    db.Column('item_id', db.Integer, db.ForeignKey('items.id'), primary_key=True),
    db.Column('category_id', db.Integer, db.ForeignKey('categories.id'), primary_key=True)
)

# --- MODELS ---
class UserModel(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)


class StoreModel(db.Model):
    __tablename__ = "stores"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)

    items = db.relationship("ItemModel", back_populates="store", lazy="dynamic")


class ItemModel(db.Model):
    __tablename__ = "items"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    price = db.Column(db.Float(precision=2), nullable=False)

    store_id = db.Column(db.Integer, db.ForeignKey("stores.id"), nullable=False)
    store = db.relationship("StoreModel", back_populates="items")

    categories = db.relationship(
        "CategoryModel",
        secondary=item_categories,
        back_populates="items"
    )


class CategoryModel(db.Model):
    __tablename__ = "categories"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False, unique=True)

    items = db.relationship(
        "ItemModel",
        secondary=item_categories,
        back_populates="categories"
    )

# --- ROUTES ---

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if UserModel.query.filter_by(username=data["username"]).first():
        return {"error": "Username already exists"}, 400

    hashed_password = generate_password_hash(data["password"])
    new_user = UserModel(username=data["username"], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return {"message": "User registered successfully"}, 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = UserModel.query.filter_by(username=data["username"]).first()
    if user and check_password_hash(user.password, data["password"]):
        access_token = create_access_token(identity=user.id)
        return {"access_token": access_token}, 200
    return {"error": "Invalid credentials"}, 401

@app.route("/")
@jwt_required()
def home():
    return {"message": "Практична 5: Аутентифікація працює!"}

@app.route("/store", methods=["POST"])
@jwt_required()
def create_store():
    data = request.get_json()
    new_store = StoreModel(name=data["name"])
    db.session.add(new_store)
    db.session.commit()
    return jsonify({"id": new_store.id, "name": new_store.name}), 201

@app.route("/item", methods=["POST"])
@jwt_required()
def create_item():
    data = request.get_json()
    store = StoreModel.query.get(data["store_id"])
    if store is None:
        return {"error": "Store not found"}, 404

    item = ItemModel(name=data["name"], price=data["price"], store_id=data["store_id"])
    db.session.add(item)
    db.session.commit()
    return jsonify({
        "id": item.id,
        "name": item.name,
        "price": item.price,
        "store": store.name
    }), 201

@app.route("/stores", methods=["GET"])
@jwt_required()
def get_stores():
    stores = StoreModel.query.all()
    result = []
    for store in stores:
        result.append({
            "id": store.id,
            "name": store.name,
            "items": [
                {
                    "id": item.id,
                    "name": item.name,
                    "price": item.price,
                    "categories": [cat.name for cat in item.categories]
                }
                for item in store.items
            ]
        })
    return jsonify(result)

@app.route("/category", methods=["POST"])
@jwt_required()
def create_category():
    data = request.get_json()
    new_category = CategoryModel(name=data["name"])
    db.session.add(new_category)
    db.session.commit()
    return jsonify({"id": new_category.id, "name": new_category.name}), 201

@app.route("/item/<int:item_id>/categories", methods=["POST"])
@jwt_required()
def assign_categories_to_item(item_id):
    item = ItemModel.query.get(item_id)
    if not item:
        return {"error": "Item not found"}, 404

    data = request.get_json()
    category_ids = data.get("category_ids", [])
    categories = CategoryModel.query.filter(CategoryModel.id.in_(category_ids)).all()

    item.categories.extend(categories)
    db.session.commit()

    return jsonify({
        "item_id": item.id,
        "categories": [c.name for c in item.categories]
    }), 200

# --- MAIN ---
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)