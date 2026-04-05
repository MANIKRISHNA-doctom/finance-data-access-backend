import express from "express";
import jwt from 'jsonwebtoken';

const authRoleMiddleware = (allowedRoles = []) => {
  return (req, res, next) => {
    const token = req.cookies?.token; 
    if (!token || token.trim() === "") {
      return res.status(401).json({ message: "No token found, you have to sign in" });
    }

    try {
      const decoded = jwt.verify(token, process.env.SECRET);

      req.user = decoded; 

      //  Role check
      if (allowedRoles.length && !allowedRoles.includes(decoded.role)) {
        return res.status(403).json({
          message: "Access denied. You are not allowed to create, update, or delete records and users."
        });
      }
      next();
    } catch (err) {
      res.clearCookie('token');
      return res.status(401).json({ message: "Invalid token , You are logged out" });
    }
  };
};

export default authRoleMiddleware;