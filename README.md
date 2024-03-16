# SIO - DETI Store

## Description

DETI Store is a made-up e-commerce store which specializes in selling DETI merchandising. It allows users to buy products, review them and even leave comments about their experience with the order. In adition to that, the user can check the details about the product they're intrested in buying and check if they are out of stock before putting an order.
For this project, two version of the website were created: one insecure and another secure, where we fixed a set of 6 vulnerabilities found on the first.


## Authors

* Joana Gomes, 104429
* Lia Cardoso, 107548
* Liliana Ribeiro, 108713
* Pedro Ponte,98059

#

## Vulnerabilities 

* **CWE-79** : Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
* **CWE-89** : Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
* **CWE-20** : Improper Input Validation
* **CWE-256** : Plaintext Storage of a Password
* **CWE-521** : Weak Password Requirements
* **CWE-434** : Unrestricted Upload of File with Dangerous Type

## Directory Structure

On the app_sec folder you can find the `secure version` of the website and on the app folder you can find the `insecure version`.

On the analysis folder you can find our `report` in markdown and pdf format alongside screenshots and videos the website interface.

    
```bash
├── app_sec
│   ├── app.py
│   ├── instance
│   │   └── test.db
│   ├── static
│   │   ├── css
│   │   ├── img
│   ├── templates
│   │   ├── html
│   ├── README.md
├── app
│   ├── app.py
│   ├── instance
│   │   └── test.db
│   ├── static
│   │   ├── css
│   │   ├── img
│   ├── templates
│   │   ├── html
│   ├── README.md
├── docker-compose.yml
├── Dockerfile
├── README.md
├── analysis.md
│   ├── report.md
│   ├── report.pdf
│   ├── screenshots
│   └── videos
```
# SIO_First_Project
