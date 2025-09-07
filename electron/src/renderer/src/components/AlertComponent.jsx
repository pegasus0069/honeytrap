import React from 'react';
import Alert from 'react-bootstrap/Alert';
import './AlertComponent.css'; // Import the CSS file for custom styles

const AlertComponent = ({ title, body, variant = 'danger', show, onClose }) => {
  return (
    <>
      {show && (
        <div className="alert-container">
          <Alert variant={variant} onClose={onClose} dismissible>
            <Alert.Heading>{title}</Alert.Heading>
            <p>{body}</p>
          </Alert>
        </div>
      )}
    </>
  );
};

export default AlertComponent;
