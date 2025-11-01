CREATE DATABASE IF NOT EXISTS pineus_tilu;
USE pineus_tilu;

CREATE TABLE users (
  id CHAR(36) PRIMARY KEY,
  name VARCHAR(100),
  email VARCHAR(100) UNIQUE,
  phone VARCHAR(30),
  password_hash VARCHAR(255)
);

CREATE TABLE bookings (
  id CHAR(36) PRIMARY KEY,
  user_id CHAR(36),
  booking_date DATETIME,
  amount DECIMAL(10,2),
  otp_hash VARCHAR(255),
  otp_salt VARCHAR(255),
  otp_expires BIGINT,
  is_verified TINYINT DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
