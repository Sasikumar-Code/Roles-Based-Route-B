/** @format */

const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();

const verifyToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json('Access Denied');

  try {
    const verified = jwt.verify(token.split(' ')[1], process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json('Invalid Token');
  }
};

const verifyRole = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json('Access Forbidden');
    }
    next();
  };
};

router.get('/admin', verifyToken, verifyRole(['Admin']), (req, res) => {
  res.json('Welcome Admin');
});

router.get('/manager', verifyToken, verifyRole(['Manager']), (req, res) => {
  res.json('Welcome Manager');
});

router.get('/employee', verifyToken, verifyRole(['Employee']), (req, res) => {
  res.json('Welcome Employee');
});

module.exports = router;
