import numpy as np

from CybORG.Simulator.Host import Host


def cart2pol(x, y):
    if x == 0.0 and y == 0.0:
        return None
    rho = np.sqrt(x**2 + y**2)
    phi = np.arctan2(y, x)
    return np.array([rho, phi])


def pol2cart(rho, phi):
    x = rho*np.cos(phi)
    y = rho*np.sin(phi)
    return np.array([x, y])


class Drone(Host):
    """A moving drone in a swarm"""

    # initialization method. Given the overall dimensions of the space, provide an initial position and velocity.
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.avoid_distance = 20.
        self.avoid_edge_distance = 20.0
        self.centroid_strength = 0.5
        self.avoid_strength = 1.
        self.align_strength = 0.3
        self.max_turn = np.pi/8.0
        self.max_velocity = 0.5
        self.inertia = 0.5
        self.follow_strength = 5.0
        self.random_force = 0.01
        self.fixed_heading = None
        self.num_moves_remaining = 0
        self.move_chance = 0.1
        self.velocity = self.np_random.uniform(-self.max_velocity, self.max_velocity, 2)
        self.update_drone_position()

    def avoidance_vector(self, neighbour_list):
        # dist = {nl.hostname: (nl.position[0]-self.position[0])**2 + (nl.position[1]-self.position[1])**2 for nl in neighbour_list}
        avoid_vector_list = [np.divide(self.avoid_distance, (self.position-nl.position), out=np.zeros(2), where=(self.position-nl.position)!=0)  for nl in neighbour_list]
        if avoid_vector_list:
            avoid_vector = np.mean(avoid_vector_list, axis=0)
            if max(abs(avoid_vector)) > 0:
                return self.avoid_strength * avoid_vector / max(abs(avoid_vector)) * self.max_velocity
        return np.zeros(2)

    def centroid_vector(self, neighbour_list):
        if neighbour_list:
            neighbour_positions = [nl.position for nl in neighbour_list] + [np.array([50., 50.])]
            average_position = np.mean(neighbour_positions, axis=0)
            centroid_disp = average_position - self.position
            return self.centroid_strength * centroid_disp / max(abs(centroid_disp)) * self.max_velocity
        else:
            return np.zeros(2)

    def align_vector(self, neighbour_list):
        if neighbour_list:
            neighbour_directions = [nl.velocity for nl in neighbour_list]
            average_velocity = np.mean(neighbour_directions, axis=0)
            return self.align_strength * average_velocity
        else:
            return np.zeros(2)

    # update speed and direction given relative positions of neighbours - normal behaviour
    def update_drone_velocity(self, neighbour_list):
        align_force = self.align_vector(neighbour_list)
        centroid_force = self.centroid_vector(neighbour_list)
        avoid_force = self.avoidance_vector(neighbour_list)
        total_vector = self.velocity + align_force + centroid_force + avoid_force + self.random_force * self.np_random.uniform(-self.max_velocity, self.max_velocity, 2)
        total_vector = self.velocity/self.inertia + total_vector/(1-self.inertia)
        self.velocity = self.max_velocity*total_vector/max(abs(total_vector))
        if min(self.position) < 10.0 or max(self.position) > 90.0:
            self.reset_drone_heading()
        if len(neighbour_list) > 3:
            self.velocity = self.velocity/2

    def update_drone_position(self):
        # update position
        self.position = self.position + self.velocity
        for i in range(2):
            self.position[i] = min(self.position[i], 100)
            self.position[i] = max(self.position[i], 0)

    def reset_drone_heading(self):
        new_heading = np.zeros(2)
        for i in [0, 1]:
            if self.position[i] < 10.0 and not self.velocity[i] > 0.0:
                new_heading[i] = self.np_random.uniform(0.0, self.max_velocity)
            elif self.position[i] > 90.0 and not self.velocity[i] < 0.0:
                new_heading[i] = -self.np_random.uniform(0.0, self.max_velocity)
            else:
                new_heading[i] = self.velocity[i]
        self.velocity = new_heading

    def update(self, state):
        """Moves drone at end of the turn"""
        drone_neighbourhood = []
        for interface in self.interfaces:
            if interface.swarm:
                drone_neighbourhood += interface.data_links
        if self.num_moves_remaining > 0:
            self.num_moves_remaining -= 1
            if min(self.position) < 10.0 or max(self.position) > 90.0:
                self.reset_drone_heading()
        elif self.np_random.random() < self.move_chance:
            self.num_moves_remaining = self.np_random.randint(5, 10)
            self.velocity = self.np_random.uniform(-self.max_velocity, self.max_velocity, 2)
        else:
            self.fixed_heading = None
            self.update_drone_velocity([state.hosts[host] for host in drone_neighbourhood if type(state.hosts[host]) == Drone and host != self.hostname])
        self.update_drone_position()
