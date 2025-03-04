from django.urls import path
from rest_framework.authtoken.views import obtain_auth_token

from . import views

urlpatterns = [

    ###################################### APIS MANAGEMENT SYSTEM ######################################################
    # Token Management
    path('token/', obtain_auth_token, name='token_obtain_pair'),
    path('token/refresh/', obtain_auth_token, name='token_refresh'),
    # Token Management

    # Authorization & Authentication
    path('check-email/', views.check_email, name='check_email'),  # update code
    path('sign-up/', views.sign_up_api_view, name='sign_up'),
    path('user-role/', views.user_role, name='user_role'),
    path('verify-otp-with-user-signup/', views.verify_otp_with_user_signup, name='verify_otp_with_user_signup'),
    path('update-user-with-licensees-and-increases-xp-levels/',
         views.update_user_with_licensees_and_increases_xp_levels,
         name='update_user_with_licensees_and_increases_xp_levels'),
    path('phone-verification-and-get-free-xp/', views.phone_verification_and_get_free_xp,
         name='phone_verification_and_get_free_xp'),
    path('update-user-personal-information-api/', views.update_user_personal_information_api,
         name='update_user_personal_information_api'),
    path('update-user-documents/', views.update_user_documents, name='update_user_documents'),
    path('login/', views.login_api_view, name='login'),
    path('logout/', views.logout_api_view, name='login'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('refresh-otp/', views.refresh_otp, name='refresh_otp'),
    path('request-reset-password/', views.request_reset_password, name='request_reset_password'),
    path('confirm-reset-password/', views.confirm_reset_password, name='confirm_reset_password'),
    path('api/v1/verify-email/', views.verify_email, name='verify_email'),  ## update code
    path('de-activate-user/', views.de_activate_user, name='de_activate_user'),
    path('activate-user/', views.activate_user, name='activate_user'),
    path('upload-profiles-and-banners/', views.upload_profiles_and_banners, name='upload_profiles_and_banners'),
    path('upload-profile-photo/', views.upload_profile_photo, name='upload_profile_photo'),
    path('profile/', views.profile, name='profile'),

    path('block-unblock-user/', views.block_unblock_user, name='block_unblock_user'),
    path('admin-delete-user/', views.admin_delete_user, name='admin_delete_user'),
    path('get-all-users/', views.get_all_users, name='get_all_users'),
    path('get-all-unblocked-users/', views.get_all_unblocked_users, name='get_all_unblocked_users'),
    path('get-all-agents/', views.get_all_agents, name='get_all_agents'),
    # Authorization & Authentication

    # Reviews Helpful & Not Helpful
    path('reviews/helpful-review/', views.helpful_review, name='helpful_review'),
    path('reviews/not-helpful-review/', views.not_helpful_review, name='not_helpful_review'),
    path('reviews/toggle-review-helpfulness/', views.toggle_review_helpfulness, name='toggle_review_helpfulness'),
    # Reviews Helpful & Not Helpful

    # Replies Helpful & Not Helpful
    path('replies/toggle-reply-helpfulness/', views.toggle_reply_helpfulness, name='toggle_reply_helpfulness'),
    # Replies Helpful & Not Helpful

    # Chat Management System
    path('chat/activate-user-agent-chat/', views.activate_user_agent_chat, name='activate_user_agent_chat'),
    path('chat/de-activate-user-agent-chat/', views.de_activate_user_agent_chat, name='de_activate_user_agent_chat'),
    path('chat/is-user-alive/', views.is_user_alive, name='is_user_alive'),
    path('chat/get-global-chat-history/', views.get_global_chat_history, name='get_global_chat_history'),
    path('chat/get-global-chats/', views.get_global_chats, name='get_global_chats'),
    path('chat/send-message-to-global-chat/', views.send_message_to_global_chat, name='send_message_to_global_chat'),
    path('chat/agent_chat_users/', views.agent_chat_users, name='agent_chat_users'),
    path('chat/get_admin_and_agent_chat_history/', views.get_admin_and_agent_chat_history,
         name='get_admin_and_agent_chat_history'),

    path('chat/conversation-messages/', views.get_conversation_messages, name='get_conversation_messages'),
    path('chat/conversation-messages-by-conversation-id/', views.get_conversation_messages_by_conversation_id,
         name='get_conversation_messages_by_conversation_id'),
    path('chat/send-message-to-agent/', views.send_message_to_agent, name='send_message_to_agent'),
    # Chat Management System

    # Reviews Management System
    path('reviews/get-reviews/', views.get_reviews, name='get_reviews'),  # (limit = 10)
    path('reviews/get-reviews-by-game-id/', views.get_reviews_game_id, name='get_reviews_game_id'),
    path('reviews/post-game-review/', views.post_game_review, name='post_game_review'),
    path('reviews/delete-game-review/', views.delete_game_review, name='delete_game_review'),
    path('reviews/get-game-rating/', views.get_game_rating, name='get_game_rating'),
    path('reviews/post-admin-reply/', views.post_admin_reply, name='post_admin_reply'),
    path('reviews/get-admin-replies/', views.get_admin_replies, name='get_admin_replies'),
    path('reviews/update-admin-reply/', views.update_admin_reply, name='update_admin_reply'),
    path('reviews/delete-admin-reply/', views.delete_admin_reply, name='delete_admin_reply'),
    path('reviews/update-game-review-ratings/', views.update_game_review_ratings, name='update_game_review_ratings'),
    # Reviews Management System

    # Games Management System
    path('games/add-game/', views.add_game, name='add_game'),
    path('games/get-game-by-name/', views.get_game_by_name, name='get_game_by_name'),
    ## update code
    path('games/add-game-rating/', views.add_game_rating, name='add_game_rating'),
    path('games/get-game-rating/', views.get_game_rating, name='get_game_rating'),
    path('games/get-available-games/', views.get_available_games, name='get_available_games'),
    path('games/get-available-games/unblocked/', views.get_available_games_unblocked,
         name='get_available_games_unblocked'),
    path('games/get-available-games-by-admin-and-agent-tokens/', views.get_available_games_by_admin_and_agent_tokens,
         name='get_available_games_by_admin_and_agent_tokens'),
    path('games/get-all-free-games/', views.get_all_free_games, name='get_all_free_games'),
    path('games/get-trending-games/', views.get_trending_games, name='get_trending_games'),
    path('games/get-upcoming-games/', views.get_upcoming_games, name='get_upcoming_games'),
    path('games/update-game/', views.update_game, name='update_game'),
    path('games/delete-game/', views.delete_game, name='delete_game'),
    path('games/redeem-game-player-scores-to-wallet/', views.redeem_game_player_scores_to_wallet,
         name='redeem_game_player_scores_to_wallet'),
    path('games/get-game-transaction-history/', views.get_game_transaction_history,
         name='get_game_transaction_history'),
    path('games/get-game-player-by-username/', views.get_game_player_by_username,
         name='get_game_player_by_username'),
    path('games/player-to-player-redemption/', views.player_to_player_redemption,
         name='player_to_player_redemption'),
    path('games/get-all-games-under-user-freeplays/', views.get_all_games_under_user_freeplays,
         name='get_all_games_under_user_freeplays'),
    ## Games Management System

    ## Admin Game Panel Management System
    path('analytics/', views.analytics, name='analytics'),
    path('admin-game-panel/create-player/', views.create_player_by_admin, name='create_player_by_admin'),
    path('admin-game-panel/create-user-agent/', view=views.CreateAgentAPIView.as_view(), name='create_agent_by_admin'),

    path('admin-game-panel/reset-game-password/', views.reset_game_password, name='reset_game_password'),
    path('admin-game-panel/get-panel-scores/', views.get_panel_scores, name='get_panel_scores'),

    path('admin-game-panel/add-score-to-player-account/', views.add_score_to_player_account,
         name='add_score_to_player_account'),
    path('admin-game-panel/redeem-score-from-player-account/', views.redeem_score_from_player_account,
         name='redeem_score_from_player_account'),

    path('admin-game-panel/get-all-player-accounts/', views.get_all_players_accounts, name='get_all_players_accounts'),
    path('admin-game-panel/get-all-my-created-players/', views.get_all_my_created_players_by_admin,
         name='get_all_my_created_players_by_admin'),

    path('admin-game-panel/get-all-my-created-games/', views.get_all_my_created_games_by_admin,
         name='get_all_my_created_games_by_admin'),
    path('admin-game-panel/get-player-score/', views.get_player_score, name='get_player_score'),
    path('admin-game-panel/get-game-status/', views.get_game_stats, name='get_game_stats'),
    path('admin-game-panel/block-player/', views.block_player, name='block_player'),
    path('admin-game-panel/block-game/', views.block_game, name='block_game'),
    path('admin-game-panel/is-free-game/', views.is_free_game, name='is_free_game'),
    path('admin-game-panel/upcoming/', views.upcoming_status, name='upcoming_status'),
    path('admin-game-panel/trending/', views.is_trending, name='is_trending'),
    path('admin-game-panel/delete-player/', views.delete_player, name='delete_player'),
    path('admin-game-panel/delete-game/', views.delete_game, name='delete_game'),
    path('admin-game-panel/update-game/', views.update_game_by_admin_agent, name='update_game_by_admin_agent'),
    ##


    path('admin-game-panel/player-has-been-notified/', views.player_has_been_notified,
         name='player_has_been_notified'),
    path('admin-game-panel/all-player-has-been-notified/', views.all_player_has_been_notified,
         name='all_player_has_been_notified'),
    path('notifications/', views.notifications,
         name='notifications'),
    path('admin-game-panel/game-has-been-notified/', views.game_has_been_notified,
         name='game_has_been_notified'),
    path('admin-game-panel/all-game-has-been-notified/', views.all_game_has_been_notified,
         name='all_game_has_been_notified'),
    ##
    ## Admin Game Panel Management System

    ## Spin Wheel Management System
    path('spin/get-spin-wheel/', views.get_spin_wheel, name='get_spin_wheel'),
    path('spin/spin-history/', views.spin_history, name='spin_history'),
    ## Spin Wheel Management System

    ## Prize Management System
    path('prizes/get-prizes/', views.get_prizes, name='get_prizes'),
    path('prizes/create-prize/', views.create_prize, name='create_prize'),
    path('prizes/get-prize-by-id/', views.get_prize_by_id, name='get_prize_by_id'),
    path('prizes/update-prize/', views.update_prize, name='update_prize'),
    path('prizes/delete-prize/', views.delete_prize, name='delete_prize'),
    ## Prize Management System

    ## Promo Code Management System
    path('promo-code/get-promo-codes/', views.get_promo_codes, name='get_promo_codes'),
    path('promo-code/create-promo-codes/', views.create_promo_code, name='create_promo_code'),
    path('promo-code/verify-promo-code/', views.verify_promo_code, name='verify_promo_code'),
    path('promo-code/get-promo-code/', views.get_promo_code_by_id, name='get_promo_code_by_id'),
    path('promo-code/delete-promo-code/', views.delete_promo_code, name='delete_promo_code'),
    ## Promo Code Management System

    ## Level Management System
    path('levels/get-levels/', views.get_levels, name='get_levels'),
    path('levels/get-level/', views.get_level_by_id, name='get_level_by_id'),
    path('levels/create-levels/', views.create_level, name='create_level'),
    path('levels/delete-level/', views.delete_level, name='delete_level'),
    path('levels/update-level/', views.update_level, name='update_level'),
    ## Level Management System

    ## Referral Management System
    path('referral/create-referral-code/', views.create_referral_code, name='create_referral_code'),
    path('referral/get-referral-codes/', views.get_referral_codes, name='get_referral_codes'),
    path('referral/verify-referral-code/', views.verify_referral_code, name='verify_referral_code'),
    path('referral/get-all-referrals-by-username/', views.get_all_referrals_by_username,
         name='get_all_referrals_by_username'),
    path('referral/delete-all-referrals/', views.delete_all_referrals, name='delete_all_referrals'),
    path('referral/delete-by-referral-key/', views.delete_referral_by_key, name='delete_referral_by_key'),
    ## Referral Management System

    ## Wallet Management System
    path('api/v1/wallet/payment/', views.handle_payment, name='handle_payment'),  # update code
    path('wallet/get-user-account-wallet/', views.get_user_account_wallet, name='get_user_account_wallet'),
    path('wallet/get-transaction-history/', views.get_transaction_history, name='get_transaction_history'),
    path('wallet/pay-by-link/', views.pay_by_link, name='pay_by_link'),  # Generate payment link
    path('wallet/verify-payment-by-order-id/', views.verify_payment_by_order_id, name='verify_payment_by_order_id'),
    path('wallet/withdraw-money-from-user-account-wallet/', views.withdraw_money_from_user_account_wallet,
         name='withdraw_money_from_user_account_wallet'),
    path('wallet/deposit-money-to-user-account-wallet/', views.deposit_money_to_user_account_wallet,
         name='deposit_money_to_user_account_wallet'),
    ## Wallet Management System

    ## Landing Page Data Management System
    path('landing/data/', views.landing_page_data, name='landing_page_data'),
    ## Landing Page Data Management System

    ## Agent Panel Management System
    path('agent-panel/create-player/', views.create_player_by_agent, name='create_player_by_agent'),
    path('agent-panel/get-all-my-created-players/', views.get_all_my_created_players_agent,
         name='get_all_my_created_players_agent'),
    path('agent-panel/reset-game-password/', views.reset_game_password_by_agent,
         name='reset_game_password_by_agent'),
    ## Agent Panel Management System

    ## User Management System
    path('user-panel/create-player/', views.create_player_by_user, name='create_player_by_user'),
    path('user-panel/get-all-game-accounts/', views.get_all_my_accounts, name='get_all_my_accounts'),
    path('user-panel/update-score/', views.update_score, name='update_score'),
    ## User Management System

    ###################################### APIS MANAGEMENT SYSTEM ######################################################

]
