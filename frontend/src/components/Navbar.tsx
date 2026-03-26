import React from 'react';
import { ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';

const Navbar: React.FC = () => {
  return (
    <nav className="bg-dark text-white p-4 shadow-lg sticky top-0 z-50">
      <div className="container mx-auto flex justify-between items-center">
        <Link to="/" className="flex items-center space-x-2 text-2xl font-bold tracking-wider hover:text-primary transition-colors duration-300">
          <ShieldCheck className="text-secondary w-8 h-8" />
          <span>WebScanPro</span>
        </Link>
        <div className="flex space-x-4">
          {/* Add navigation links here if needed */}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;