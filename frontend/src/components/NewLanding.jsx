import React, { useState, useEffect, useRef } from "react";
import {
  Button,
  Grid,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
} from "@mui/material";
import axios from "axios";
import styled from "@emotion/styled";
import { motion } from "framer-motion";
import { useAuth0 } from "@auth0/auth0-react";
import Form from "./FormInput";
import HorizontalBars from "./Dashboard";
import Home from "../Routes/Homepage";
import MapWithWebSocket from "./MapComponent";
import GoogleButton from "./GoogleButton";
import "../Newlanding.css";
import "./authen.css";
import { Paper, Text, Group } from "@mantine/core";

const AnimatedGrid = styled(motion.div)`
  display: flex;
  justify-content: center;
  margin-top: 30px;
  margin: 10px;
  gap: 7px;
`;

const AnimatedButton = styled(motion.button)`
  background-color: #3f51b5;
  color: white;
  border: none;
  border-radius: 4px;
  padding: 10px 20px;
  cursor: pointer;
  &:hover {
    background-color: #303f9f;
  }
`;

const buttonVariants = {
  hover: {
    scale: 1.1,
    boxShadow: "0px 0px 8px rgb(0, 0, 0)",
  },
};

const gridVariants = {
  hidden: { opacity: 0, y: -20 },
  visible: {
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.5,
    },
  },
};

const RedButton = styled(AnimatedButton)`
  background-color: #f44336;
  &:hover {
    background-color: #d32f2f;
  }
`;

function NewLanding() {
  const [trip, setTrip] = useState({
    started: false,
    startTime: null,
    elapsedTime: 0,
    id: null,
    username: "",
  });
  const [activeComponent, setActiveComponent] = useState(null);
  const intervalIdRef = useRef(null);
  const [openModal, setOpenModal] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [username, setUsername] = useState("");

  const { loginWithRedirect, user, isAuthenticated: auth0IsAuthenticated } = useAuth0();

  useEffect(() => {
    window.onbeforeunload = () => {
      window.scrollTo(0, 0);
    };
  }, []);

  useEffect(() => {
    const savedTrip = JSON.parse(localStorage.getItem("trip"));
    if (savedTrip && savedTrip.started) {
      const elapsedTime = new Date() - new Date(savedTrip.startTime);
      setTrip({ ...savedTrip, elapsedTime });
      const savedActiveComponent = localStorage.getItem("activeComponent");
      setActiveComponent(savedActiveComponent || "ADD_TRAVEL_LOG");
    }
  }, []);

  useEffect(() => {
    // Check if the username is already stored in localStorage
    const storedUsername = localStorage.getItem('username');
    if (storedUsername) {
      setUsername(storedUsername);
      setIsAuthenticated(true); // Assuming that having a username means authenticated
    } else {
      // Fetch the username from the backend after the OAuth flow
      fetchUsernameFromBackend();
    }
  }, []);

  const initiateOAuth = async () => {
    try {
      // Generate code verifier and challenge
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = await generateCodeChallenge(codeVerifier);
  
      // Define code verifier function
      function generateCodeVerifier(length = 128) {
        const array = new Uint8Array(length);
        window.crypto.getRandomValues(array);
        return array
          .reduce((acc, byte) => acc + String.fromCharCode(byte), '')
          .replace(/[^\w\d]/g, '')
          .slice(0, length);
      }
  
      // Define code challenge function
      async function generateCodeChallenge(codeVerifier) {
        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashBase64 = btoa(String.fromCharCode(...hashArray))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
        return hashBase64;
      }
  
      // Save code verifier in local storage
      localStorage.setItem('code_verifier', codeVerifier);
  
      // Define OAuth parameters
      const CLIENT_ID = '607168653915-f5sac4tb4mvuslkj2l0cit912nupdkr3.apps.googleusercontent.com'; // Replace with your actual client ID
      const REDIRECT_URI = 'https://9f6d-2407-5200-403-5cfe-bc23-708c-e033-a4d2.ngrok-free.app/callback'; // Your callback URL
      const SCOPES = 'email profile openid'; // Adjust scopes as needed
  
      // Create the authorization URL
      const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=${encodeURIComponent(SCOPES)}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
  
      // Redirect to Google's OAuth endpoint
      window.location.href = authUrl;
    } catch (error) {
      console.error('Error initiating OAuth:', error);
    }
  };
  

  const fetchUsernameFromBackend = async () => {
    try {
      const code = localStorage.getItem('auth_code');
      
      if (!code) {
        throw new Error('Authorization code is missing from local storage');
      }
      
      const response = await axios.get('http://localhost:8080/callback', {
        params: { code }
      });
  
      const userInfo = response.data;
      console.log('User info response:', userInfo);
      
      const userName = userInfo.name || userInfo.email || userInfo.username;
      if (!userName) {
        throw new Error('Username or email is not defined in response');
      }
      
      localStorage.setItem('username', userName);
      setUsername(userName);
      setIsAuthenticated(true);
      console.log('Username set:', userName);
    } catch (error) {
      console.error('Error fetching user info:', error.response ? error.response.data : error);
      if (error.response && error.response.status === 404) {
        console.error('The /callback endpoint is not found. Please check the server-side implementation.');
      }
    }
  };
  

  useEffect(() => {
    if (isAuthenticated) {
      const fetchUserInfo = async () => {
        try {
          // Fetch user info for subsequent requests
          const response = await axios.get('http://localhost:8080/api/userinfo');
          const userInfo = response.data;
          const userName = userInfo.name || userInfo.username || userInfo.email;
          localStorage.setItem('username', userName);
          setUsername(userName);
          console.log('Fetched username:', userName);
        } catch (error) {
          console.error('Error fetching user info:', error);
        }
      };

      fetchUserInfo();
    }
  }, [isAuthenticated]);



  

  useEffect(() => {
    const intervalId = setInterval(async () => {
      try {
        const response = await axios.post(
          "http://localhost:8080/get_trip_state",
          { username }
        );
        if (response.status === 200) {
          const tripData = response.data;
          setTrip({
            started: tripData.tripStarted,
            startTime: new Date(tripData.tripStartTime),
            elapsedTime: tripData.elapsedTime,
            id: tripData.tripId,
            username,
          });
        }
      } catch (error) {
        console.error("Error polling trip status:", error);
      }
    }, 115000);

    return () => clearInterval(intervalId);
  }, [username]);

  useEffect(() => {
    localStorage.setItem("trip", JSON.stringify(trip));
  }, [trip]);

  useEffect(() => {
    localStorage.setItem("activeComponent", activeComponent);
  }, [activeComponent]);



  const handleStartClick = async () => {
    try {
      const storedUsername = localStorage.getItem('username');
      if (!storedUsername) throw new Error('Username is not defined');

      console.log('Attempting to start trip with client name:', storedUsername);

      const response = await axios.post('http://localhost:8080/start_trip', {
        username: storedUsername,
      });
      if (response.status === 200) {
        console.log('Trip started successfully:', response.data);
        const currentTime = new Date();
        setTrip({
          started: true,
          startTime: currentTime,
          elapsedTime: 0,
          id: response.data.tripId,
          username: storedUsername,
        });
        setActiveComponent('ADD_TRAVEL_LOG');
      } else {
        console.error('Error starting trip: Unexpected response status', response.status);
      }
    } catch (error) {
      console.error('Error starting trip:', error);
    }
  };

  const handleStopClick = async () => {
    try {
      const storedUsername = localStorage.getItem('username');
      if (!storedUsername) {
        throw new Error('Username is not defined in localStorage');
      }

      const response = await axios.post(
        'http://localhost:8080/end_trip',
        { username: storedUsername },
        { headers: { 'Content-Type': 'application/json' } }
      );

      if (response.status === 200) {
        setTrip({
          started: false,
          startTime: null,
          elapsedTime: 0,
          id: null,
          username: '',
        });
        localStorage.removeItem('trip');
        if (intervalIdRef.current) {
          clearInterval(intervalIdRef.current);
        }
        setActiveComponent(null);
      } else {
        console.error('Error ending trip: Unexpected response status', response.status);
      }
    } catch (error) {
      console.error(
        'Error ending trip:',
        error.response ? error.response.data : error.message
      );
      if (error.response && error.response.status === 409) {
        alert(
          'No active trip found. Please ensure a trip is in progress before trying to end it.'
        );
      }
    }
  };

  useEffect(() => {
    if (trip.started && trip.startTime) {
      intervalIdRef.current = setInterval(() => {
        setTrip((prevTrip) => ({
          ...prevTrip,
          elapsedTime: new Date() - new Date(prevTrip.startTime),
        }));
      }, 1000);
    } else {
      clearInterval(intervalIdRef.current);
    }

    return () => clearInterval(intervalIdRef.current);
  }, [trip.started, trip.startTime]);

  const formatElapsedTime = (elapsedTime) => {
    const seconds = Math.floor(elapsedTime / 1000) % 60;
    const minutes = Math.floor(elapsedTime / (1000 * 60)) % 60;
    const hours = Math.floor(elapsedTime / (1000 * 60 * 60));

    return `${hours}h: ${minutes}m: ${seconds}s`;
  };

  const toggleComponent = (component) => {
    setActiveComponent((prevComponent) =>
      prevComponent === component ? null : component
    );
  };

  const handleGoogleLogin = () => {
    loginWithRedirect({
      connection: "google-oauth2",
    });
  };

  // useEffect(() => {
  //   if (!isAuthenticated) {
  //     initiateOAuth();
  //   }
  // }, [isAuthenticated]);

  const handleLogin =() =>{
    initiateOAuth();
  }


  const handleAuthSuccess = (username) => {
    setIsAuthenticated(true);
    setUsername(username);
    localStorage.setItem("username", username);
    setOpenModal(true);
    console.log("This is the username", username);
  };

  const renderAuthForm = () => (
    <div className="authentication-form">
      <Paper radius="md" p="xl" withBorder>
        <Text size="lg" weight={500}>
          Welcome to Trip Logger
        </Text>
        <Group grow mb="md" mt="md">
          <GoogleButton radius="xl" onClick={handleGoogleLogin}>
            Wordlink
          </GoogleButton>
        </Group>
      </Paper>
    </div>
  );

  return (
    <>
      <Grid container justifyContent="center" spacing={2} display={"flex"}>
        <Grid item xs={12} sm={6}>
          {!trip.started && (
            <>
              <AnimatedGrid initial="hidden" animate="visible" variants={gridVariants}>
                <Grid item>
                  <AnimatedButton
                    variants={buttonVariants}
                    whileHover="hover"
                    onClick={handleLogin}
                  >
                    Login
                  </AnimatedButton>
                </Grid>
                <Grid item>
                  <AnimatedButton
                    variants={buttonVariants}
                    whileHover="hover"
                    onClick={() => setOpenModal(true)}
                  >
                    Start Trip
                  </AnimatedButton>
                </Grid>
                <Grid item>
                  <AnimatedButton
                    variants={buttonVariants}
                    whileHover="hover"
                    onClick={() => toggleComponent("TRAVEL_LOG")}
                  >
                    Travel Log
                  </AnimatedButton>
                </Grid>
                <Grid item>
                  <AnimatedButton
                    variants={buttonVariants}
                    whileHover="hover"
                    onClick={() => toggleComponent("USER_MAP")}
                  >
                    User Map
                  </AnimatedButton>
                </Grid>
              </AnimatedGrid>
              {openModal && (
                <Dialog
                  open={openModal}
                  onClose={() => setOpenModal(false)}
                  aria-labelledby="alert-dialog-title"
                  aria-describedby="alert-dialog-description"
                >
                  <DialogTitle id="alert-dialog-title">
                    {"Start Trip Confirmation"}
                  </DialogTitle>
                  <DialogContent>
                    <DialogContentText id="alert-dialog-description">
                      Are you sure you want to start the trip?
                    </DialogContentText>
                  </DialogContent>
                  <DialogActions>
                    <Button onClick={() => setOpenModal(false)} color="primary">
                      No
                    </Button>
                    <Button onClick={handleStartClick} color="primary" autoFocus>
                      Yes
                    </Button>
                  </DialogActions>
                </Dialog>
              )}
            </>
          )}

          {trip.started && (
            <>
              <h1 className="text-3xl"> Welcome {username} </h1>
              <p className="text-xl" style={{ margin: "10px" }}>
                Trip started at:{" "}
                <span className="font-bold">
                  {trip.elapsedTime
                    ? formatElapsedTime(trip.elapsedTime)
                    : "00:00:00"}
                </span>
              </p>

              <AnimatedGrid initial="hidden" animate="visible" variants={gridVariants}>
                <Grid item>
                  <AnimatedButton
                    variants={buttonVariants}
                    whileHover="hover"
                    onClick={() => toggleComponent("ADD_TRAVEL_LOG")}
                  >
                    {activeComponent === "ADD_TRAVEL_LOG"
                      ? "Hide Travel Log"
                      : "Show Travel Log"}
                  </AnimatedButton>
                </Grid>
                <Grid item>
                  <RedButton
                    variants={buttonVariants}
                    whileHover="hover"
                    onClick={handleStopClick}
                  >
                    End Trip
                  </RedButton>
                </Grid>
                <Grid item>
                  <AnimatedButton
                    variants={buttonVariants}
                    whileHover="hover"
                    onClick={() => toggleComponent("TRAVEL_LOG_DETAILS")}
                  >
                    {activeComponent === "TRAVEL_LOG_DETAILS"
                      ? "Hide Travel Log Details"
                      : "Show Travel Log Details"}
                  </AnimatedButton>
                </Grid>
                <Grid item>
                  <AnimatedButton
                    variants={buttonVariants}
                    whileHover="hover"
                    onClick={() => toggleComponent("USER_MAP_DETAILS")}
                  >
                    {activeComponent === "USER_MAP_DETAILS"
                      ? "Hide User Map Details"
                      : "Show User Map Details"}
                  </AnimatedButton>
                </Grid>
              </AnimatedGrid>
            </>
          )}

          {activeComponent === "ADD_TRAVEL_LOG" && <Form />}
          {activeComponent === "TRAVEL_LOG" && <Home />}
          {activeComponent === "USER_MAP" && <MapWithWebSocket />}
          {activeComponent === "TRAVEL_LOG_DETAILS" && <Home />}
          {activeComponent === "USER_MAP_DETAILS" && <MapWithWebSocket />}

          {!trip.started && <HorizontalBars />}
        </Grid>
      </Grid>
    </>
  );
}

export default NewLanding;
