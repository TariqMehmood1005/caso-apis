# API Endpoints Documentation

## Authentication & Token Management

- `POST /api/token/` - Obtain authentication token
- `POST /api/token/refresh/` - Refresh authentication token

## User Authorization & Authentication

- `POST /api/sign-up/` - User sign-up
- `GET /api/user-role/` - Retrieve user role
- `POST /api/verify-otp-with-user-signup/` - Verify OTP during user sign-up
- `POST /api/update-user-with-licensees-and-increases-xp-levels/` - Update user with licensees and increase XP levels
- `POST /api/phone-verification-and-get-free-xp/` - Phone verification to receive free XP
- `POST /api/update-user-personal-information-api/` - Update user personal information
- `POST /api/update-user-documents/` - Upload user documents
- `POST /api/login/` - User login
- `POST /api/verify-otp/` - Verify OTP
- `POST /api/refresh-otp/` - Refresh OTP
- `POST /api/request-reset-password/` - Request password reset
- `POST /api/confirm-reset-password/` - Confirm password reset
- `POST /api/de-activate-user/` - Deactivate user
- `POST /api/activate-user/` - Activate user
- `POST /api/upload-profiles-and-banners/` - Upload profiles and banners
- `POST /api/upload-profile-photo/` - Upload profile photo
- `GET /api/profile/` - Retrieve user profile
- `POST /api/block-unblock-user/` - Block/unblock a user
- `POST /api/admin-delete-user/` - Admin deletes a user
- `GET /api/get-all-users/` - Retrieve all users
- `GET /api/get-all-unblocked-users/` - Retrieve all unblocked users
- `GET /api/get-all-agents/` - Retrieve all agents

## Review Management

- `POST /api/reviews/helpful-review/` - Mark a review as helpful
- `POST /api/reviews/not-helpful-review/` - Mark a review as not helpful
- `POST /api/reviews/toggle-review-helpfulness/` - Toggle review helpfulness
- `GET /api/reviews/get-reviews/` - Get all reviews
- `GET /api/reviews/get-reviews-by-game-id/` - Get reviews by game ID
- `POST /api/reviews/post-game-review/` - Post a game review
- `DELETE /api/reviews/delete-game-review/` - Delete a game review
- `GET /api/reviews/get-game-rating/` - Get game rating
- `POST /api/reviews/post-admin-reply/` - Post admin reply to a review
- `GET /api/reviews/get-admin-replies/` - Get admin replies
- `PUT /api/reviews/update-admin-reply/` - Update admin reply
- `DELETE /api/reviews/delete-admin-reply/` - Delete admin reply
- `PUT /api/reviews/update-game-review-ratings/` - Update game review ratings
- `PUT /api/reviews/update-admin-reply-ratings/` - Update admin reply ratings

## Game Management

- `POST /api/games/add-game/` - Add a game
- `POST /api/games/add-game-rating/` - Add a game rating
- `GET /api/games/get-game-rating/` - Retrieve game rating
- `GET /api/games/get-available-games/` - Get available games
- `GET /api/games/get-available-games/unblocked/` - Get unblocked available games
- `GET /api/games/get-trending-games/` - Get trending games
- `GET /api/games/get-upcoming-games/` - Get upcoming games
- `PUT /api/games/update-game/` - Update game details
- `DELETE /api/games/delete-game/` - Delete a game

## Admin Game Panel

- `GET /api/admin-game-panel/get-panel-scores/` - Retrieve panel scores
- `POST /api/admin-game-panel/create-player/` - Create player by admin
- `POST /api/admin-game-panel/create-user-agent/` - Create agent by admin
- `POST /api/admin-game-panel/reset-game-password/` - Reset game password
- `DELETE /api/admin-game-panel/delete-player/` - Delete player
- `DELETE /api/admin-game-panel/delete-game/` - Delete game
- `PUT /api/admin-game-panel/update-game/` - Update game by admin/agent

## Chat Management

- `POST /api/chat/send-message-to-global-chat/` - Send message to global chat
- `GET /api/chat/get-global-chat-history/` - Retrieve global chat history
- `GET /api/chat/get-global-chats/` - Retrieve global chats
- `POST /api/chat/send-message-to-agent/` - Send message to an agent

## Spin Wheel Management

- `GET /api/spin/get-spin-wheel/` - Retrieve spin wheel details
- `GET /api/spin/spin-history/` - Retrieve spin history

## Prize Management

- `GET /api/prizes/get-prizes/` - Retrieve all prizes
- `POST /api/prizes/create-prize/` - Create a prize
- `GET /api/prizes/get-prize-by-id/` - Retrieve a prize by ID
- `PUT /api/prizes/update-prize/` - Update a prize
- `DELETE /api/prizes/delete-prize/` - Delete a prize

## Promo Code Management

- `GET /api/promo-code/get-promo-codes/` - Retrieve all promo codes
- `POST /api/promo-code/create-promo-codes/` - Create a promo code
- `POST /api/promo-code/verify-promo-code/` - Verify a promo code
- `GET /api/promo-code/get-promo-code/` - Retrieve a promo code by ID
- `DELETE /api/promo-code/delete-promo-code/` - Delete a promo code

## Level Management

- `GET /api/levels/get-levels/` - Retrieve all levels
- `POST /api/levels/create-levels/` - Create a level
- `GET /api/levels/get-level/` - Retrieve a level by ID
- `PUT /api/levels/update-level/` - Update a level
- `DELETE /api/levels/delete-level/` - Delete a level

## Referral Management

- `POST /api/referral/create-referral-code/` - Create a referral code
- `GET /api/referral/get-referral-codes/` - Retrieve all referral codes
- `POST /api/referral/verify-referral-code/` - Verify a referral code

## Notes

- All API requests should be prefixed with `/api/`
- Use authentication tokens for protected routes
- Refer to API documentation for request parameters and response formats

