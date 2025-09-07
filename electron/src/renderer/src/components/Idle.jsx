import { useState, useEffect } from 'react'
import axios from 'axios';
import logoName from '../assets/logoName.png'
import Button from 'react-bootstrap/Button';
import 'bootstrap/dist/css/bootstrap.min.css';
import './Idle.css'

function Idle({queue,enqueue,dequeue,peek,isEmpty,server,alert,setAlert}) {

  const [ip, setIp] = useState('')
  const [mac, setMac] = useState('')

  useEffect(() => {
    if (!isEmpty()) {
      const latestEvent = peek();
      setIp(latestEvent.src_ip);
      setMac(latestEvent.mac_address);
    }
    else {
      setIp('');
      setMac('');
    }
  }, [queue]);
  
  const [tap, setTap] = useState(false)
  function logoNameOnClick(){
    if (!isEmpty()){
      setTap(true);
    }
    console.log("Clicked")
  }
  function allowIP(ip){
    dequeue()
    setTap(false)
  }
  async function removeIP() {
      dequeue();
      setTap(false);
    try {
      const response = await fetch(server+"/block_mac", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ mac_address: mac}),
      });
      const data = await response.json();
      console.log(data);
      
      
    } catch (error) {
      console.error("Error blocking MAC address:", error);
    }
  }

  return (
    !tap?
  <div className='idlePage'>
    <img onClick={logoNameOnClick} className='logoName' src={logoName} alt="" />
    <span className='alertSpan span'>{isEmpty()?"No Alerts Detected":"Alert Detected"}</span>

  </div>:
  // ---------------If tapped-----------------------
  <div className='idlePage'>
  <div className='row1'>
    <img className='row1Logo' src={logoName} alt="" />
    <span className='ipd span'>IP Address Detected</span>

  </div>
  <div className='row2'>
    <span className='span'>{ip}</span>
    <span className='span'>Do you want to remove this from the network?</span>
  </div>
  <div className='row3'>
  <Button onClick={removeIP} variant="danger" size='lg'>Remove</Button>
  <Button onClick={allowIP} variant="success" size='lg'>Allow</Button>
    
  </div>
</div>
    
  )
}

export default Idle
