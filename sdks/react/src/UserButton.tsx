import React, { useState, useEffect, useRef } from 'react';
import { IDaaSClient } from '@idaas/core';
import { useIDaaS } from './IDaaSProvider';

export interface UserButtonProps {
    apiUrl?: string; // Optional - uses IDaaSProvider if not specified
    onSignOut?: () => void;
    showEmail?: boolean;
    showName?: boolean;
    menuItems?: MenuItem[];
    theme?: 'light' | 'dark';
    className?: string;
}

export interface MenuItem {
    label: string;
    icon?: React.ReactNode;
    onClick: () => void;
    divider?: boolean;
}

export function UserButton({
    apiUrl: propApiUrl,
    onSignOut,
    showEmail = true,
    showName = true,
    menuItems = [],
    theme = 'light',
    className = '',
}: UserButtonProps) {
    const [user, setUser] = useState<any>(null);
    const [isOpen, setIsOpen] = useState(false);
    const dropdownRef = useRef<HTMLDivElement>(null);
    
    // Use context if apiUrl not provided
    const context = propApiUrl ? null : useIDaaS();
    const apiUrl = propApiUrl || context?.config.apiUrl || 'http://localhost:3000';
    
    const client = new IDaaSClient({ apiUrl });

    useEffect(() => {
        loadUser();
    }, []);

    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
                setIsOpen(false);
            }
        };

        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const loadUser = async () => {
        try {
            const userData = await client.getCurrentUser();
            setUser(userData);
        } catch (error) {
            console.error('Failed to load user:', error);
        }
    };

    const handleSignOut = async () => {
        try {
            await client.signOut();
            sessionStorage.removeItem('jwt');
            if (onSignOut) {
                onSignOut();
            } else {
                window.location.href = '/sign-in';
            }
        } catch (error) {
            console.error('Sign out failed:', error);
        }
    };

    if (!user) {
        return null;
    }

    const isDark = theme === 'dark';
    const bgHover = isDark ? 'hover:bg-gray-700' : 'hover:bg-gray-100';
    const dropdownBg = isDark ? 'bg-gray-800 border-gray-700' : 'bg-white border-gray-200';
    const textColor = isDark ? 'text-white' : 'text-gray-900';
    const textSecondary = isDark ? 'text-gray-400' : 'text-gray-500';
    const itemHover = isDark ? 'hover:bg-gray-700' : 'hover:bg-gray-100';

    const initials = user.firstName && user.lastName
        ? `${ user.firstName.charAt(0) }${ user.lastName.charAt(0) } `
        : user.email.charAt(0).toUpperCase();

    const displayName = user.firstName && user.lastName
        ? `${ user.firstName } ${ user.lastName } `
        : user.email.split('@')[0];

    return (
        <div ref={dropdownRef} className={`relative ${ className } `}>
            <button
                onClick={() => setIsOpen(!isOpen)}
                className={`flex items - center space - x - 3 px - 3 py - 2 rounded - lg ${ bgHover } transition - colors`}
            >
                <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center text-white font-bold text-sm">
                    {initials}
                </div>
                {(showName || showEmail) && (
                    <div className="hidden md:block text-left">
                        {showName && (
                            <div className={`text - sm font - medium ${ textColor } `}>
                                {displayName}
                            </div>
                        )}
                        {showEmail && (
                            <div className={`text - xs ${ textSecondary } `}>
                                {user.email}
                            </div>
                        )}
                    </div>
                )}
                <svg
                    className={`w - 4 h - 4 ${ textSecondary } transition - transform ${ isOpen ? 'rotate-180' : '' } `}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
            </button>

            {isOpen && (
                <div className={`absolute right - 0 mt - 2 w - 64 ${ dropdownBg } border rounded - lg shadow - xl z - 50`}>
                    {/* User Info Header */}
                    <div className={`p - 3 border - b ${ isDark ? 'border-gray-700' : 'border-gray-200' } `}>
                        <div className={`text - sm font - semibold ${ textColor } `}>
                            {displayName}
                        </div>
                        <div className={`text - xs ${ textSecondary } mt - 1`}>
                            {user.email}
                        </div>
                    </div>

                    {/* Menu Items */}
                    <div className="p-2">
                        {/* Custom menu items */}
                        {menuItems.map((item, index) => (
                            <React.Fragment key={index}>
                                {item.divider && (
                                    <div className={`border - t ${ isDark ? 'border-gray-700' : 'border-gray-200' } my - 2`} />
                                )}
                                <button
                                    onClick={() => {
                                        item.onClick();
                                        setIsOpen(false);
                                    }}
                                    className={`w - full flex items - center space - x - 3 px - 3 py - 2 text - sm ${ textColor } ${ itemHover } rounded - lg transition - colors text - left`}
                                >
                                    {item.icon && <span>{item.icon}</span>}
                                    <span>{item.label}</span>
                                </button>
                            </React.Fragment>
                        ))}

                        {menuItems.length > 0 && (
                            <div className={`border - t ${ isDark ? 'border-gray-700' : 'border-gray-200' } my - 2`} />
                        )}

                        {/* Default menu items */}
                        <button
                            onClick={() => {
                                window.location.href = '/profile';
                                setIsOpen(false);
                            }}
                            className={`w - full flex items - center space - x - 3 px - 3 py - 2 text - sm ${ textColor } ${ itemHover } rounded - lg transition - colors text - left`}
                        >
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                            </svg>
                            <span>Profile</span>
                        </button>

                        <button
                            onClick={() => {
                                window.location.href = '/security';
                                setIsOpen(false);
                            }}
                            className={`w - full flex items - center space - x - 3 px - 3 py - 2 text - sm ${ textColor } ${ itemHover } rounded - lg transition - colors text - left`}
                        >
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                            </svg>
                            <span>Security</span>
                        </button>

                        <div className={`border - t ${ isDark ? 'border-gray-700' : 'border-gray-200' } my - 2`} />

                        <button
                            onClick={handleSignOut}
                            className={`w - full flex items - center space - x - 3 px - 3 py - 2 text - sm text - red - 600 dark: text - red - 400 hover: bg - red - 50 dark: hover: bg - red - 900 / 20 rounded - lg transition - colors text - left`}
                        >
                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                            </svg>
                            <span>Sign Out</span>
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
}
