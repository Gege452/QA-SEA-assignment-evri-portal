from app import app
from app import db, Courier, CourierAdmin, CourierQuery
from werkzeug.security import generate_password_hash
from random import randint, choice
from faker import Faker

# Declaring for Faker library to use GB
fake = Faker('en_GB')

def seed_data():
    # We are dropping all tables with the rows inside them and creating all the tables again
    db.drop_all()
    db.create_all()

    # Create 10 admins
    # the email will be firstName.lastName@evri.com in all lowercase
    for i in range(1, 11):
        newname = fake.name()
        newemail = newname.replace(" ",".").lower()
        admin = CourierAdmin(
            name=newname,
            email=f"{newemail}@evri.com",
            password_hash=generate_password_hash("admin123")
        )
        db.session.add(admin)
    db.session.commit()

    # Create 10 couriers
    couriers = []
    for i in range(1, 11):
        newnamecourier = fake.name()
        newemailcourier = newnamecourier.replace(" ",".")
        courier = Courier(
            name=newnamecourier,
            region=choice(['North', 'South', 'East', 'West']),
            phone=fake.cellphone_number(),
            email=f"{newemailcourier}@test.mail",
            pin_hash=generate_password_hash("1234"),
            crtd_by_cra_id=randint(1, 10)
        )
        db.session.add(courier)
        couriers.append(courier)
    db.session.commit()

    # Create 3 queries per courier (30 total)
    for courier in couriers:
        for _ in range(3):
            query = CourierQuery(
                title=fake.catch_phrase(),
                message=fake.paragraph(nb_sentences=3),
                submitted_by=courier.cr_id
            )
            db.session.add(query)
    db.session.commit()
    print("Seeding complete: 10 admins, 10 couriers, 30 queries")

if __name__ == '__main__':
    with app.app_context():
        seed_data()
