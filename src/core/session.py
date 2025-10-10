from datetime import datetime
from typing import Any, Dict, Optional, List
from uuid import uuid4

class Session:
    #represents a single session with hardware connection and state.
    def __init__(self):
        self.session_id: str = str(uuid4())
        self.hardware: Optional[Any] = None  # Will be HardwareInterface later
        self.config: Dict[str, Any] = {}
        self.created_at: datetime = datetime.now()
        self.last_activity: datetime = datetime.now()
        self.is_active: bool = True

    def connect_hardware(self, interface_type: str, **kwargs):
            self.config['interface_type'] = interface_type
            self.config.update(kwargs)
            self.touch()

    def disconnect_hardware(self):
        self.hardware = None
        self.touch()

    def update_config(self, key: str, value: Any):
        self.config[key] = value
        self.touch()

    def get_config(self, key:str, default: Any = None) -> Any:
        return self.config.get(key, default)
    
    def touch(self):
         self.last_activity = datetime.now()

    def __repr__(self) -> str:
         status = "active" if self.is_active else "inactive"
         hw_status = "connected" if self.hardware else "disconnected"
         return(
              f"Session(id={self.session_id[:8]}..., "
              f"status={status}, hardware={hw_status})"
         )
    

class SessionManager:
    def __init__(self):
          self.sessions: Dict[str, Session] = {}
          self.current_session_id: Optional[str] = None
    
    def create_session(self, **config) -> Session:
         session = Session()
         session.config.update(config)

         self.sessions[session.session_id] = session

         if self.current_session_id is None:
              self.current_session_id = session.session_id

         return session
    
    def destroy_session(self, session_id: str):
         if session_id not in self.sessions:
              raise KeyError(f"Session not found: {session_id}")
         session = self.sessions[session_id]

         session.disconnect_hardware()
         session.is_active = False
         del self.sessions[session_id]
         if self.current_session_id == session_id:
              if self.sessions:
                   self.current_session_id = next(iter(self.sessions.keys()))
              else:
                   self.current_session_id = None

    def get_session(self, session_id: str) -> Optional[Session]:
         return self.sessions.get(session_id)
    
    def list_sessions(self) -> List[Session]:
         return sorted(self.sessions.values(), key=lambda s: s.created_at)
    
    def set_current(self, session_id: str):
        if session_id not in self.sessions:
             raise KeyError(f"Session not found: {session_id}")
        if self.current_session_id:
            old_session = self.sessions.get(self.current_session_id)
            if old_session:
                  old_session.touch()
            self.current_session_id = session_id
            self.sessions[session_id].touch()
            
    def get_current(self) -> Optional[Session]:
        if self.current_session_id:
            return self.sessions.get(self.current_session_id)
        return None
    

            
    
