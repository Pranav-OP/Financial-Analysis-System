// src/components/ProtectedRoute.jsx
import React from "react";
import { Navigate } from "react-router-dom";

function ProtectedRoute({ children, allowedRoles = [] }) {
  const token = localStorage.getItem("access_token");
  const userRole = localStorage.getItem("role"); // we'll store role after login

  if (!token) return <Navigate to="/login" replace />;

  if (allowedRoles.length > 0 && !allowedRoles.includes(userRole)) {
    return (
      <div style={{ textAlign: "center", marginTop: "50px" }}>
        <h2>Unauthorized</h2>
        <p>You do not have permission to view this page.</p>
      </div>
    );
  }

  return children;
}

export default ProtectedRoute;
