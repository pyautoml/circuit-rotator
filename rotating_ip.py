import os
import json
import httpx
from stem import Signal
from dotenv import load_dotenv
from typing import Final, List
from stem.control import Controller
from abc import ABC, abstractmethod
from pydantic import BaseModel, Field, ConfigDict, PrivateAttr


load_dotenv()

class AbstractProxy(ABC):
    @abstractmethod
    def rotate_proxy(self):
        pass

# --------------
# FREE PROXIES
# --------------
class TorProxy(BaseModel, AbstractProxy):
    tor_ip: str = None
    local_ip: str = None
    tor_data: dict = {}
    max_rotations: int = 10
    tor_mount_proxy: dict = {}
    tor_port: Final[int] = int(os.getenv("PORT"))
    used_proxies: List[str] = Field(default_factory=list)
    ip_service_url: Final[str] = os.getenv("SERVICE_URL")
    _tor_password: str = PrivateAttr(default=os.getenv("PASSWORD"))
    max_circuit_dirtness: Final[int] = int(os.getenv("MAX_CIRCUIT_DIRTINESS", 10))
    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if not self._tor_password:
            raise ValueError(
                "Tor password is not set. Ensure the PASSWORD environment variable is configured."
            )

        if not self.ip_service_url:
            raise ValueError(
                "Service URL is not set. Ensure the SERVICE_URL environment variable is configured."
            )

        self.local_ip: str = self.__check_local_proxy()
        self.tor_ip: str = self.__check_tor_proxy()
        self.tor_mount_proxy: dict = {
            "http://": httpx.HTTPTransport(proxy=os.getenv("SOCKET")),
            "https://": httpx.HTTPTransport(proxy=os.getenv("SOCKET")),
        }

    def __repr__(self):
        return f"TorProxy(tor_ip={self.tor_ip}, local_ip={self.local_ip}, max_rotations={self.max_rotations})"

    def make_request_through_tor(self, url: str) -> str:
        try:
            with httpx.Client(mounts=self.tor_mount_proxy) as client:
                response = client.get(url)
                response.raise_for_status()
                return response.text
        except httpx.RequestError as e:
            raise RuntimeError(f"Failed to make a request through Tor: {e}")

    def tor_data_dump(self) -> str:
        return json.dumps(self.tor_data, indent=4)

    def __extract_circuit_status(self, data: str) -> List[str]:
        return data.splitlines()

    def __renew_tor_circuit(self) -> None:
        """Sends the NEWNYM signal to the Tor control port to request a new identity."""
      
          with Controller.from_port(port=self.tor_port) as controller:
              controller.authenticate(password=self._tor_password)
              controller.signal(Signal.NEWNYM)
              self.tor_data["circuit_status"] = self.__extract_circuit_status(
                  controller.get_info("circuit-status")
              )

    def __check_local_proxy(self) -> str:
        response = httpx.get(self.ip_service_url)
        response.raise_for_status()
        return response.text

    def __check_tor_proxy(self) -> str:
        return self.make_request_through_tor(url=self.ip_service_url)

    def __generate_new_tor_proxy(self) -> str:
        self.__renew_tor_circuit()
        return self.__check_tor_proxy()

    def rotate_proxy(self, unique: bool = False, prevent_ips_match: bool = True) -> str:
        for _ in range(self.max_rotations):
            new_tor_ip: str = self.__generate_new_tor_proxy()

            if prevent_ips_match and new_tor_ip == self.local_ip:
                continue

            if unique and new_tor_ip in self.used_proxies:
                if len(self.used_proxies) >= self.max_rotations:
                    raise RuntimeError("All possible IPs have been exhausted.")
                continue

            self.used_proxies.append(new_tor_ip)
            return new_tor_ip
        raise RuntimeError(
            "Max proxy rotations reached. Failed to get a unique new IP."
        )

def show_example():
    """Run this function in main()"""
    proxy = TorProxy()
  
    for i in range(0, 3):
        print("-------------------------------------------------------------")
        print("Local IP: ", proxy.local_ip)
        print(f"Rotated proxy: ", proxy.rotate_proxy(unique=True))
        print(f"IP seen by an external server: {proxy.make_request_through_tor(proxy.ip_service_url)}")
        print(" ------------------------------------------------------------\n")
  
