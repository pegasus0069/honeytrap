import React, { useState, useEffect } from 'react'
import axios from 'axios';
import logo from './assets/ukcs.png'
import logoName from './assets/logoName.png'
import Button from 'react-bootstrap/Button';
import 'bootstrap/dist/css/bootstrap.min.css';
import './App.css'
import Modal from 'react-bootstrap/Modal';
import Dropdown from 'react-bootstrap/Dropdown';
import Form from 'react-bootstrap/Form';

import AlertComponent from './components/AlertComponent'
import Table from 'react-bootstrap/Table'
import Idle from './components/Idle'

function App() {
  const server = "http://localhost:5000"
  const [queue, setQueue] = useState([]); // State to store the queue
  // Add an element to the end of the queue
  const enqueue = (item) => {
    setQueue((prevQueue) => [...prevQueue, item]);
  };
  // Remove and return the first element of the queue
  const dequeue = () => {
    if (queue.length === 0) {
      console.error("Queue is empty. Cannot dequeue.");
      return null;
    }
    const [first, ...rest] = queue;
    setQueue(rest);
    return first;
  };
  // Return the first element without removing it
  const peek = () => {
    if (queue.length === 0) {
      console.error("Queue is empty. Nothing to peek.");
      return null;
    }
    return queue[0];
  };
  // Get the size of the queue
  const size = () => queue.length;
  // Check if the queue is empty
  const isEmpty = () => queue.length === 0;

  const fetchAndEnqueue = async () => {
    try {
      const response = await fetch(server+"/get_latest_event");
      if (!response.ok) {
        throw new Error("Network response was not ok");
      }
      const data = await response.json();
      if (data.message) {
        console.log(data.message);
      } else {
        setQueue((prevQueue) => [...prevQueue, data]);
      }
    } catch (error) {
      console.error("Failed to fetch data:", error);
    }
    console.log("Queue length:")
    console.log(queue.length)
    console.log(isEmpty())
  };
  // Fetch data when the component mounts
useEffect(() => {
  const interval = setInterval(fetchAndEnqueue, 1000); // Fetch every 1 second
  return () => clearInterval(interval); // Cleanup on unmount
}, []);

  const [autoblockUi, setAutoblockUi] = useState("OFF")
  const [pending, setPending] = useState(null)
  const [showPasswordAlert, setShowPasswordAlert] = useState(false); //UI Alert

  //Email
  const [emailModal, setEmailModal] = useState(false);
  const handleCloseEmailModal = () => setEmailModal(false);
  const handleShowEmailModal = () =>{
    setEmail(currentEmail);
    setEmailModal(true);
  } 
  const [currentEmail, setCurrentEmail] = useState("");
  const [email, setEmail] = useState(currentEmail);


    //Blacklist
  const [blacklistModal, setBlacklistModal] = useState(false);
  const handleCloseBlacklistModal = () => setBlacklistModal(false);
  const handleShowBlacklistModal = () => setBlacklistModal(true);
  const [blacklist, setBlacklist] = useState([]); // Example JSON data
  const [newIp, setNewIp] = useState('');

const fetchBlacklist = async () => {
  try {
    const response = await axios.get(server+'/get_blacklist');
    if (response.status === 200) {
      console.log('Blacklist Data:', response.data); // You can use the blacklist data here
      setBlacklist(response.data)
      return response.data;
    }
  } catch (error) {
    if (error.response) {
      // Server responded with a status other than 200
      console.error('Error Response:', error.response.data.message);
    } else if (error.request) {
      // No response was received
      console.error('No response received:', error.request);
    } else {
      // Something else happened
      console.error('Error:', error.message);
    }
  }
};
// Fetch blacklist every 500ms
useEffect(() => {
  const interval = setInterval(fetchBlacklist, 500); // Fetch every 500ms
  return () => clearInterval(interval); // Cleanup on unmount
}, []);
  //Fetch email
  useEffect(() => {
    const fetchEmail = async () => {
      try {
        const response = await axios.get(server + '/get_email');
        const { receiver_email } = response.data;
        if (receiver_email) {
          setCurrentEmail(receiver_email);
          setEmail(receiver_email);
        }
        console.log('Email fetched:', receiver_email);
      } catch (error) {
        console.error('Error fetching email:', error);
      }
    };
  
    const intervalId = setInterval(async () => {
      if (!currentEmail) {
        fetchEmail();
      } else {
        clearInterval(intervalId); // Clear interval once email is fetched
      }
    }, 500);
  
    return () => clearInterval(intervalId); // Clean up the interval when component unmounts or changes
  }, [currentEmail]);

  const fetchAutoblock = async () => {
    try {
      const response = await axios.get(server + '/get_autoblock');
      const { autoblock } = response.data;
      if (autoblock) {
        setAutoblockUi(autoblock);
      }
      console.log('Autoblock:', autoblock);
    } catch (error) {
      console.error('Error fetching autoblock:', error);
    }
  };
  // Fetch autoblock when the app opens
useEffect(() => {
  fetchAutoblock();
}, []);

  
  const handleEmailSubmit = async () => {
    try {
        const response = await axios.post(server + '/change_email', {
            new_email: email
        });
        setCurrentEmail(email);
        setEmail(''); // Clear the email field
        handleCloseEmailModal(); // Close the modal
    } catch (error) {
        if (error.response) {
            console.log('Failed to change email: ' + error.response.data);
        } else {
            console.log('Failed to change email: ' + error.message);
        }
    }
};

const toggleAutoblock = async () => {
  const newAutoblock = autoblockUi === 'OFF' ? 'ON' : 'OFF';
  try {
      const response = await axios.post(server + '/change_autoblock', {
          autoblock: newAutoblock
      });
      window.alert(response.data);
      setAutoblockUi(newAutoblock);
  } catch (error) {
      if (error.response) {
          console.log('Failed to change autoblock: ' + error.response.data);
      } else {
          console.log('Failed to change autoblock: ' + error.message);
      }
  }
};
  function authenticateProcess(process){
    setPending(process)
    handleShowPasswordMenu()
  }
  


  // Handle adding a new IP address
  const handleAddIp = () => {
    if (newIp && !blacklist.includes(newIp)) {
      setBlacklist([...blacklist, newIp]);
      setNewIp('');
    } else {
      alert("Invalid or duplicate IP address");
    }
  };
  // Handle removing an IP address
  const handleRemoveIp = (ip) => {
    setBlacklist(blacklist.filter(item => item !== ip));
  };

  //Password
  const [passwordMenu, setPasswordMenu] = useState(false);
  const [password, setPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');

  const [newPasswordMenu, setNewPasswordMenu] = useState(false);
  const handleClosePasswordMenu = () => setPasswordMenu(false);
  const handleShowPasswordMenu = () => setPasswordMenu(true);
  const handleCloseNewPasswordMenu = () => setNewPasswordMenu(false);
  const handleShowNewPasswordMenu = () => setNewPasswordMenu(true);

  const handleChangePassword = async () => {
    try {
        console.log(newPassword);
        const response = await axios.post(server + '/change_password', {
            new_password: newPassword
        });
        setNewPassword('');
        handleCloseNewPasswordMenu();
        window.alert(response.data);

    } catch (error) {
        if (error.response) {
            console.log('Failed to change password: ' + error.response.data);
        } else {
            console.log('Failed to change password: ' + error.message);
        }
    }
};

  const handlePasswordSubmit = async () => {
    console.log('Password submitted:', password);
    try {
      const response = await axios.post(server + '/verify_password', {
          password: password
      });
      if (response.data.status === '1') {
          if (pending==="email") {
            handleShowEmailModal();
            setPending(null);
          }
          else if (pending==="blacklist") {
            handleShowBlacklistModal();
            setPending(null);
          }
          else if (pending==="newPassword"){
            handleShowNewPasswordMenu();
            setPending(null);
          }
          else if (pending==="autoblock"){
            handleShowNewPasswordMenu();
            setPending(null);
          }

      } else {
          setShowPasswordAlert(true);
      }
  } catch (error) {
      setShowPasswordAlert(true);
      if (error.response) {
          console.log('Failed to verify password: ' + error.response.data);
      } else {
          console.log('Failed to verify password: ' + error.message);
      }
  }
    handleClosePasswordMenu(); // Close the password modal
    setPassword(''); // Clear the password field
  };
  async function unblock(mac) {
    try {
      const response = await fetch(server + "/unblock_mac", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ mac_address: mac }),
      });
  
      const responseText = await response.text(); // Log the raw response text
      console.log("Raw response:", responseText);
  
      const data = JSON.parse(responseText); // Attempt to parse the response as JSON
      console.log(data);
  
    } catch (error) {
      console.error("Error blocking MAC address:", error);
      console.log(mac);
    }
  }

  return (
    <div className={isEmpty()? 'mainContainer' : 'mainContainerAlert'}>
      <img className='logo' src={logo} alt="" />
      <Dropdown className='dropdown'>
      <Dropdown.Toggle className='dropdownToggle' variant="success" id="dropdown-basic">
      </Dropdown.Toggle>

      <Dropdown.Menu>
      <Dropdown.Item onClick={() => authenticateProcess("email")}>Alert Email</Dropdown.Item>
      <Dropdown.Item onClick={() => authenticateProcess("blacklist")}>Blacklist</Dropdown.Item>
      <Dropdown.Item onClick={() => authenticateProcess("newPassword")}>Change Password</Dropdown.Item>
      <Dropdown.Item onClick={() => toggleAutoblock()} >Autoblock: {autoblockUi}</Dropdown.Item>
      </Dropdown.Menu>
    </Dropdown>

      <Idle queue={queue} peek={peek} enqueue={enqueue} dequeue={dequeue} server={server} 
      isEmpty={isEmpty}></Idle>

              {/*Password Modal*/}
<Modal
        aria-labelledby="password-modal"
        centered
        show={passwordMenu}
        onHide={handleClosePasswordMenu}
      >
        <Modal.Header closeButton>
          <Modal.Title id="password-modal">Enter Password</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <div className="form-group">
            <input
              type="password"
              id="passwordInput"
              className="form-control"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
            />
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="primary" onClick={handlePasswordSubmit}>
            Submit
          </Button>
        </Modal.Footer>
      </Modal>
      {/*Change Password Modal*/}
<Modal
        aria-labelledby="password-modal"
        centered
        show={newPasswordMenu}
        onHide={handleCloseNewPasswordMenu}
      >
        <Modal.Header closeButton>
          <Modal.Title id="password-modal">Enter New Password</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <div className="form-group">
            <input
              type="password"
              id="passwordInput"
              className="form-control"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Enter your password"
            />
          </div>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="primary" onClick={handleChangePassword}>
            Submit
          </Button>
        </Modal.Footer>
      </Modal>

      {/*Email Modal*/}
      <Modal
        aria-labelledby="email-modal"
        centered
        show={emailModal}
        onHide={handleCloseEmailModal}
      >
        <Modal.Header closeButton>
          <Modal.Title id="email-modal">Enter Email</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <div className="form-group">
            <input
              type="email"
              id="emailInput"
              className="form-control"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Enter your email"
            />
          </div>
        </Modal.Body>
        <Modal.Footer>
          
          <Button variant="primary" onClick={handleEmailSubmit}>
            Submit
          </Button>
        </Modal.Footer>
      </Modal>

      {/*Blacklist Modal*/}

      <Modal show={blacklistModal} onHide={handleCloseBlacklistModal} centered>
      <Modal.Header closeButton>
        <Modal.Title>Manage Blacklist</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <div className="form-group mb-3">
          <Form.Control
            type="text"
            placeholder="Enter IP address"
            value={newIp}
            onChange={(e) => setNewIp(e.target.value)}
          />
          <Button variant="primary" className="mt-2" onClick={handleAddIp}>
            Add IP
          </Button>
          <Table striped bordered hover className='blackTable'>
            <thead>
              <tr>
                <th>MAC Address</th>
                <th>IP Address</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {blacklist.map((item, index) => (
                <tr key={index}>
                  <td>{item.mac_address}</td>
                  <td>{item.src_ip}</td>
                  <td>
                    <Button variant="danger" onClick={() => unblock(item.mac_address)}>
                      Unblock
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
        <div style={{ maxHeight: '200px', overflowY: 'auto' }}>

</div>

      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={handleCloseBlacklistModal}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>

    <AlertComponent
        className="passwordAlert"
        title="Invalid Password"
        
        variant="danger"
        show={showPasswordAlert}
        onClose={() => setShowPasswordAlert(false)}
      />
    </div>
  )
}

export default App
