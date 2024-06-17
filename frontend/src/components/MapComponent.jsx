import React, { useState, useEffect } from "react";
import axios from "axios";
import "leaflet/dist/leaflet.css";
import { MapContainer, TileLayer, Marker } from "react-leaflet";
import { Modal, Box, Typography, CircularProgress, Button } from "@mui/material"; // Import Button from @mui/material
import MapData from "../Routes/Home";

const MapWithWebSocket = () => {
  const [socket, setSocket] = useState(null);
  const [mapCenter, setMapCenter] = useState([27.6714893, 85.3120526]);
  const [zoomLevel, setZoomLevel] = useState(13);
  const [openModal, setOpenModal] = useState(false);
  const [locationData, setLocationData] = useState([]);
  const [selectedLocation, setSelectedLocation] = useState(null);
  const [loading, setLoading] = useState(true); // Track loading state

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get("http://localhost:8080/get-form-data");
        setLocationData(response.data);
      } catch (error) {
        console.error("Error fetching location data:", error);
      } finally {
        setLoading(false); // Set loading to false whether fetch succeeded or failed
      }
    };

    fetchData();
  }, []);

  const handleMarkerClick = (location) => {
    setSelectedLocation(location);
    setOpenModal(true);
  };

  if (loading) {
    return <CircularProgress />; // Show loading indicator while fetching data
  }

  return (
    <div>
      {locationData && locationData.length > 0 ? (
        <MapContainer center={mapCenter} zoom={zoomLevel} style={{ height: "400px", margin: "10px 0" }}>
          <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
          {locationData.map((location, index) => (
            <Marker
              key={index}
              position={[location.latitude, location.longitude]}
              eventHandlers={{ click: () => handleMarkerClick(location) }}
            />
          ))}
        </MapContainer>
      ) : (
        <Typography>No location data available</Typography>
      )}

      <Modal
        open={openModal}
        onClose={() => setOpenModal(false)}
        aria-labelledby="modal-title"
        aria-describedby="modal-description"
      >
        <Box sx={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: 400, bgcolor: 'background.paper', boxShadow: 24, p: 4 }}>
          <Typography id="modal-title" variant="h6" component="h2">
            Travel Log Details
          </Typography>
          {selectedLocation && <MapData locationData={selectedLocation} />}
          <Button onClick={() => setOpenModal(false)} color="error" variant="contained" sx={{ mt: 2 }}>
            Close
          </Button>
        </Box>
      </Modal>
    </div>
  );
};

export default MapWithWebSocket;
