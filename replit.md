# Overview

This is a Node.js web application built with Express.js that provides user authentication, file upload capabilities, and basic data management functionality. The application uses EJS as the templating engine and includes both local and Facebook authentication strategies. It appears to be designed for a service-oriented platform with user registration, payment tracking, and review management features.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Backend Framework
- **Express.js** - Chosen as the main web framework for its simplicity and robust middleware ecosystem
- **EJS templating** - Server-side rendering for dynamic HTML pages with embedded JavaScript
- **In-memory data storage** - Currently uses JavaScript arrays for temporary data storage (users, payments, reviews, adminUsers)

## Authentication System
- **Passport.js** with multiple strategies:
  - Local Strategy for email/password authentication
  - Facebook Strategy for social login integration
- **bcrypt** for password hashing and security
- **express-session** for session management

## File Management
- **Multer** middleware for handling file uploads
- Static file serving through Express for uploaded content
- Dedicated uploads directory for file storage

## Frontend Architecture
- Static CSS styling with gradient backgrounds and modern UI elements
- Responsive design with flexbox layout
- Form-based user interactions

## Security Features
- Password hashing with bcrypt
- Session-based authentication
- Input validation through body-parser middleware

## Data Models
The application manages several data entities:
- **Users** - User registration and profile information
- **Payments** - Payment transaction records
- **Reviews** - User review and feedback system
- **Admin Users** - Administrative access with pre-seeded admin account

# External Dependencies

## Core Dependencies
- **express** (^5.1.0) - Web application framework
- **ejs** (^3.1.10) - Templating engine for server-side rendering
- **passport** (^0.7.0) - Authentication middleware
- **passport-local** (^1.0.0) - Local authentication strategy
- **passport-facebook** (^3.0.0) - Facebook OAuth integration
- **bcrypt** (^6.0.0) - Password hashing library
- **express-session** (^1.18.2) - Session management
- **multer** (^2.0.2) - File upload handling
- **body-parser** (^2.2.0) - Request body parsing middleware

## Development Dependencies
- **@types/node** (^22.13.11) - TypeScript definitions for Node.js

## Social Media Integration
- Facebook OAuth for social authentication (requires Facebook App configuration)

## File System Dependencies
- Local file system for upload storage
- Static asset serving for CSS and uploaded files

Note: The application currently uses in-memory storage which is not persistent. A database solution like PostgreSQL or MongoDB would be recommended for production use.