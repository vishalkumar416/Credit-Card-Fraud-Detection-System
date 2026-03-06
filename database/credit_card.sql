CREATE DATABASE credit_card_db;
USE credit_card_db;
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    phone VARCHAR(20) NULL,
    password VARCHAR(255) NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
SELECT * FROM users;

CREATE TABLE reports (
    id INT PRIMARY KEY AUTO_INCREMENT,
    customer_id INT NOT NULL,
    amount DOUBLE NOT NULL,
    is_international INT NOT NULL,
    fraud_prediction VARCHAR(50) NOT NULL,
    fraud_probability DOUBLE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_customer
    FOREIGN KEY (customer_id)
    REFERENCES users(id)
    ON DELETE CASCADE
) ENGINE=InnoDB;
SELECT * FROM reports;
