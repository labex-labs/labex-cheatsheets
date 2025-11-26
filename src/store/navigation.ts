import { acceptHMRUpdate, defineStore } from 'pinia'

interface NavbarNavigationItem {
  name: string
  path: string
  internal?: boolean
}

export const useNavigationStore = defineStore('navigation', {
  state: () => ({
    navbarNavigation: [] as NavbarNavigationItem[],
    mainNavigation: [
      {
        name: 'Getting Started',
        path: '/',
      }
    ],
    cheatsheetNavigation: [
      {
        name: 'Linux',
        path: '/linux',
        updated: false,
      },
      {
        name: 'DevOps',
        path: '/devops',
        updated: false,
      },
      {
        name: 'Cybersecurity',
        path: '/cybersecurity',
        updated: false,
      },
      {
        name: 'Kali Linux',
        path: '/kali',
        updated: false,
      },
      {
        name: 'Database',
        path: '/database',
        updated: false,
      },
      {
        name: 'Data Science',
        path: '/datascience',
        updated: false,
      },
      {
        name: 'Red Hat Enterprise Linux',
        path: '/rhel',
        updated: false,
      },
      {
        name: 'CompTIA',
        path: '/comptia',
        updated: false,
      },
      {
        name: 'Docker',
        path: '/docker',
        updated: false,
      },
      {
        name: 'Kubernetes',
        path: '/kubernetes',
        updated: false,
      },
      {
        name: 'Python',
        path: '/python',
        updated: false,
      },
      {
        name: 'Git',
        path: '/git',
        updated: false,
      },
      {
        name: 'Shell',
        path: '/shell',
        updated: false,
      },
      {
        name: 'Nmap',
        path: '/nmap',
        updated: false,
      },
      {
        name: 'Wireshark',
        path: '/wireshark',
        updated: false,
      },
      {
        name: 'Hydra',
        path: '/hydra',
        updated: false,
      },
      {
        name: 'Java',
        path: '/java',
        updated: false,
      },
      {
        name: 'SQLite',
        path: '/sqlite',
        updated: false,
      },
      {
        name: 'PostgreSQL',
        path: '/postgresql',
        updated: false,
      },
      {
        name: 'MySQL',
        path: '/mysql',
        updated: false,
      },
      {
        name: 'Redis',
        path: '/redis',
        updated: false,
      },
      {
        name: 'MongoDB',
        path: '/mongodb',
        updated: false,
      },
      {
        name: 'Golang',
        path: '/golang',
        updated: false,
      },
      {
        name: 'C++',
        path: '/cpp',
        updated: false,
      },
      {
        name: 'C',
        path: '/c-programming',
        updated: false,
      },
      {
        name: 'Jenkins',
        path: '/jenkins',
        updated: false,
      },
      {
        name: 'Ansible',
        path: '/ansible',
        updated: false,
      },
      {
        name: 'Pandas',
        path: '/pandas',
        updated: false,
      },
      {
        name: 'NumPy',
        path: '/numpy',
        updated: false,
      },
      {
        name: 'scikit-learn',
        path: '/sklearn',
        updated: false,
      },
      {
        name: 'Matplotlib',
        path: '/matplotlib',
        updated: false,
      },
      {
        name: 'Web Development',
        path: '/web-development',
        updated: false,
      },
      {
        name: 'HTML',
        path: '/html',
        updated: false,
      },
      {
        name: 'CSS',
        path: '/css',
        updated: false,
      },
      {
        name: 'JavaScript',
        path: '/javascript',
        updated: false,
      },
      {
        name: 'React',
        path: '/react',
        updated: false,
      },
    ],
  }),
})

if (import.meta.hot) {
  import.meta.hot.accept(acceptHMRUpdate(useNavigationStore, import.meta.hot))
}
