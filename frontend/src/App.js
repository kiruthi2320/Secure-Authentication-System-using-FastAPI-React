// App.js
import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [view, setView] = useState('login');
  const [username, setUsername] = useState('');
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState('');
  const [user, setUser] = useState(null);
  const [agree, setAgree] = useState(false);
  const [captcha, setCaptcha] = useState(false);
  const [message, setMessage] = useState('');

  const reset = () => {
    setUsername('');
    setFullName('');
    setEmail('');
    setPassword('');
    setAgree(false);
    setCaptcha(false);
    setMessage('');
  };

const login = async () => {
  setMessage('');
  
  // ✅ Check if fields are empty before making the API call
  if (!username.trim() || !password.trim()) {
    setMessage('❌ Please fill the Required fields');
    return;
  }

  try {
    const response = await axios.post('http://127.0.0.1:8000/token',
      new URLSearchParams({ username, password }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const accessToken = response.data.access_token;
    setToken(accessToken);
    setMessage('✅ Login successful!');

    const userRes = await axios.get('http://127.0.0.1:8000/me', {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    setUser(userRes.data);
  } catch (err) {
    setMessage('❌ Login failed: Invalid credentials');
  }
};


  const register = async () => {
    setMessage('');
    if (!agree || !captcha) {
      setMessage('❌ Please check all required fields');
      return;
    }
    try {
      const form = new URLSearchParams();
      form.append('username', username);
      form.append('password', password);
      form.append('email', email);
      form.append('full_name', fullName);

      const res = await axios.post('http://127.0.0.1:8000/register', form);
      setMessage('✅ ' + res.data.message);
      reset();
      setMessage('✅ Registration successful! You can now log in.');
      setView('login');
    } catch (err) {
      setMessage('❌ ' + (err.response?.data?.detail || 'Registration failed'));
    }
  };

  return (
    
    <div className="container">
      <div className="left-panel"></div>

      <div className="right-panel">
        <div className="login-box">
          <div className="logo"><i className="fas fa-cube"></i></div>
          <h2>{view === 'login' ? '👋 Welcome Back' : 'Create Account'}</h2>
          <p>{view === 'login' ? 'Ready to explore your secure dashboard ?' : 'Please fill out the details below'}</p>

          {view === 'register' && (
            <>
              <div className="input-group">
                <i className="fas fa-user"></i>
                <input value={fullName} onChange={e => setFullName(e.target.value)} placeholder="Full Name" />
              </div>
              <div className="input-group">
                <i className="fas fa-envelope"></i>
                <input type="email" value={email} onChange={e => setEmail(e.target.value)} placeholder="Email" />
              </div>
            </>
          )}

          <div className="input-group">
            <i className="fas fa-user-circle"></i>
            <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Username" />
          </div>

          <div className="input-group">
            <i className="fas fa-lock"></i>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Password" />
          </div>

          {view === 'register' && (
            <>
              <small className="password-note">Password must be strong (min 8 chars, upper/lowercase, number, symbol)</small>
              <div className="checkbox">
                <input type="checkbox" checked={captcha} onChange={() => setCaptcha(!captcha)} />
                I'm not a robot
              </div>
              <div className="checkbox">
                <input type="checkbox" checked={agree} onChange={() => setAgree(!agree)} />
                I agree to the terms (for auth only)
              </div>
            </>
          )}

          <button className="btn" onClick={view === 'login' ? login : register}>
            {view === 'login' ? 'Sign In' : 'Register'}
          </button>

          <div className="register">
            {view === 'login' ? (
              <>New here?<span onClick={() => { setView('register'); reset(); }}> Register now</span></>
            ) : (
              <>Already registered?<span onClick={() => { setView('login'); reset(); }}> Login</span></>
            )}
          </div>

          {message && <p className="message">{message}</p>}

          {/* 👋 Welcome message shown only after login */}
          {view === 'login' && token && user && (
            <p className="welcome-msg">👋 Welcome, {user.username}</p>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
